"""
Detection endpoints — trigger Sigma detection runs and browse results.

IMPORTANT — route ordering: GET /detections/history and
GET /detections/statistics are literal paths that must be registered
BEFORE GET /detections/{id} in this file. FastAPI/Starlette match a
route's path template structurally (not by the {id} type annotation) and
try routes in registration order, so "history"/"statistics" would
otherwise be swallowed by {id} and fail UUID conversion — the exact bug
found and fixed in Part 7 (see app/api/v1/router.py's docstring).

run/run-file/run-all are declared as regular `def` (not `async def`) so
FastAPI offloads them to its threadpool, same rationale as Part 6's
parse/reparse endpoints.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.dependencies.auth import get_current_active_user
from app.dependencies.rbac import require_permissions
from app.dependencies.services import get_audit_service, get_detection_service
from app.models.enums import RiskLevel
from app.models.user import User
from app.schemas.base import PaginatedResponseSchema, ResponseSchema
from app.schemas.detection import (
    DetectionAnalyticsOut,
    DetectionEvidenceOut,
    DetectionFeedbackRequest,
    DetectionQualityMetricsOut,
    DetectionRunSummary,
    DetectionStatistics,
    SigmaDetectionOut,
)
from app.security.permissions import Permission
from app.services.audit_service import AuditService
from app.services.detection_service import DetectionService

router = APIRouter(prefix="/detections", tags=["Detections"])


@router.post(
    "/run/{parsed_log_id}",
    response_model=ResponseSchema[DetectionRunSummary],
    summary="Run Sigma detection against a single parsed log entry",
)
def run_detection_on_log(
    parsed_log_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    detection_service: DetectionService = Depends(get_detection_service),
) -> ResponseSchema:
    summary = detection_service.detect_one_log(parsed_log_id, current_user)
    return ResponseSchema(
        success=True,
        message=f"{summary.detections_created} detection(s) created from 1 event.",
        data=summary,
    )


@router.post(
    "/run-file/{security_log_id}",
    response_model=ResponseSchema[DetectionRunSummary],
    summary="Run Sigma detection against every parsed record from one uploaded file",
)
def run_detection_on_file(
    security_log_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    detection_service: DetectionService = Depends(get_detection_service),
) -> ResponseSchema:
    summary = detection_service.detect_uploaded_file(security_log_id, current_user)
    return ResponseSchema(
        success=True,
        message=f"{summary.detections_created} detection(s) created from {summary.events_scanned} event(s).",
        data=summary,
    )


@router.post(
    "/run-all",
    response_model=ResponseSchema[DetectionRunSummary],
    summary="Run Sigma detection against every parsed log visible to the requesting user",
)
def run_detection_on_all(
    current_user: User = Depends(get_current_active_user),
    detection_service: DetectionService = Depends(get_detection_service),
) -> ResponseSchema:
    summary = detection_service.detect_all(current_user)
    return ResponseSchema(
        success=True,
        message=f"{summary.detections_created} detection(s) created from {summary.events_scanned} event(s).",
        data=summary,
    )


@router.get(
    "/history",
    response_model=PaginatedResponseSchema[SigmaDetectionOut],
    summary="Chronological detection history, optionally scoped to one file or one parsed log",
    dependencies=[Depends(require_permissions(Permission.SIGMA_VIEW))],
)
def get_detection_history(
    security_log_id: uuid.UUID | None = Query(default=None),
    parsed_log_id: uuid.UUID | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    current_user: User = Depends(get_current_active_user),
    detection_service: DetectionService = Depends(get_detection_service),
) -> PaginatedResponseSchema:
    items, total = detection_service.get_history(
        requesting_user=current_user,
        security_log_id=security_log_id,
        parsed_log_id=parsed_log_id,
        skip=skip,
        limit=limit,
    )
    return PaginatedResponseSchema(data=list(items), total=total, skip=skip, limit=limit)


@router.get(
    "/statistics",
    response_model=ResponseSchema[DetectionStatistics],
    summary="Aggregate statistics over detections (scoped to your own uploads unless you hold LOG_READ_ANY)",
    dependencies=[Depends(require_permissions(Permission.SIGMA_VIEW))],
)
def get_detection_statistics(
    current_user: User = Depends(get_current_active_user),
    detection_service: DetectionService = Depends(get_detection_service),
) -> ResponseSchema:
    stats = detection_service.get_statistics(current_user)
    return ResponseSchema(success=True, data=stats)


@router.get(
    "/quality-metrics",
    response_model=ResponseSchema[DetectionQualityMetricsOut],
    summary="Get detection quality metrics (TP rate, FP rate, accuracy from analyst verdicts)",
    dependencies=[Depends(require_permissions(Permission.SIGMA_VIEW))],
)
def get_detection_quality_metrics(
    current_user: User = Depends(get_current_active_user),
    detection_service: DetectionService = Depends(get_detection_service),
) -> ResponseSchema:
    metrics = detection_service.get_quality_metrics()
    return ResponseSchema(success=True, data=metrics)


@router.get(
    "/analytics",
    response_model=ResponseSchema[DetectionAnalyticsOut],
    summary="Get comprehensive detection analytics, trends, endpoints, and rule efficacy metrics",
    dependencies=[Depends(require_permissions(Permission.SIGMA_VIEW))],
)
def get_detection_analytics(
    current_user: User = Depends(get_current_active_user),
    detection_service: DetectionService = Depends(get_detection_service),
) -> ResponseSchema:
    analytics = detection_service.get_analytics(current_user)
    return ResponseSchema(success=True, data=analytics)



@router.get(
    "",
    response_model=PaginatedResponseSchema[SigmaDetectionOut],
    summary="List/search detections (paginated, filterable, sortable)",
    dependencies=[Depends(require_permissions(Permission.SIGMA_VIEW))],
)
def list_detections(
    parsed_log_id: uuid.UUID | None = Query(default=None),
    security_log_id: uuid.UUID | None = Query(default=None),
    matched_rule: str | None = Query(default=None),
    rule_category: str | None = Query(default=None),
    severity: RiskLevel | None = Query(default=None),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    sort_by: str = Query(default="detection_timestamp", pattern="^(detection_timestamp|created_at|severity|confidence)$"),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    current_user: User = Depends(get_current_active_user),
    detection_service: DetectionService = Depends(get_detection_service),
) -> PaginatedResponseSchema:
    items, total = detection_service.list_detections(
        requesting_user=current_user,
        parsed_log_id=parsed_log_id,
        security_log_id=security_log_id,
        matched_rule=matched_rule,
        rule_category=rule_category,
        severity=severity,
        date_from=date_from,
        date_to=date_to,
        skip=skip,
        limit=limit,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return PaginatedResponseSchema(data=list(items), total=total, skip=skip, limit=limit)


@router.get(
    "/{detection_id}/mitre",
    response_model=ResponseSchema,
    summary="Get MITRE ATT&CK mapping for a specific detection",
    dependencies=[Depends(require_permissions(Permission.SIGMA_VIEW))],
)
def get_detection_mitre(
    detection_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    detection_service: DetectionService = Depends(get_detection_service),
) -> ResponseSchema:
    detection = detection_service.get_detection_or_404(detection_id, current_user)
    mitre_techniques = [
        {
            "id": str(t.id),
            "technique_id": t.technique_id,
            "technique_name": t.technique_name,
            "tactic": t.tactic,
            "reference_url": t.reference_url,
        }
        for t in getattr(detection, "mitre_techniques", [])
    ]
    return ResponseSchema(
        success=True,
        data={
            "detection_id": str(detection.id),
            "rule_title": detection.rule_title,
            "matched_rule": detection.matched_rule,
            "mitre_tactics": getattr(detection, "mitre_tactics", []),
            "mitre_techniques": mitre_techniques,
        },
    )


@router.get(
    "/{detection_id}/evidence",
    response_model=ResponseSchema[DetectionEvidenceOut],
    summary="Get 'Why Detected?' evidence, matched fields, and rule condition",
    dependencies=[Depends(require_permissions(Permission.SIGMA_VIEW))],
)
def get_detection_evidence(
    detection_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    detection_service: DetectionService = Depends(get_detection_service),
) -> ResponseSchema:
    evidence = detection_service.get_evidence(detection_id)
    return ResponseSchema(success=True, data=evidence)


@router.post(
    "/{detection_id}/feedback",
    response_model=ResponseSchema[SigmaDetectionOut],
    summary="Record human analyst feedback / ground truth verdict for a detection",
    dependencies=[Depends(require_permissions(Permission.SIGMA_VIEW))],
)
def record_detection_feedback(
    detection_id: uuid.UUID,
    req: DetectionFeedbackRequest,
    current_user: User = Depends(get_current_active_user),
    detection_service: DetectionService = Depends(get_detection_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> ResponseSchema:
    updated = detection_service.record_analyst_feedback(detection_id, req.verdict, req.note)
    audit_service.log(
        action="DETECTION_FEEDBACK",
        user=current_user,
        object_type="SIGMA_DETECTION",
        object_id=str(detection_id),
        details={"verdict": req.verdict, "note": req.note, "rule": updated.matched_rule},
    )
    return ResponseSchema(success=True, message=f"Feedback '{req.verdict}' recorded.", data=updated)


@router.get(
    "/{detection_id}",
    response_model=ResponseSchema[SigmaDetectionOut],
    summary="Get a single detection by id",
    dependencies=[Depends(require_permissions(Permission.SIGMA_VIEW))],
)
def get_detection(
    detection_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    detection_service: DetectionService = Depends(get_detection_service),
) -> ResponseSchema:
    detection = detection_service.get_detection_or_404(detection_id, current_user)
    return ResponseSchema(success=True, data=detection)

