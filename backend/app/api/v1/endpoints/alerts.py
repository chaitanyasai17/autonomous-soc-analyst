"""
Alert management endpoints — triage queue, status transitions, assignment, and auto-generation.
"""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query, status

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_alert_service, get_audit_service
from app.models.enums import AlertStatus, RiskLevel
from app.models.user import User
from app.schemas.alert import (
    AlertAssignRequest,
    AlertCreate,
    AlertOut,
    AlertStatisticsOut,
    AlertStatusUpdate,
    AutoGenerateAlertsResponse,
)
from app.schemas.base import PaginatedResponseSchema, ResponseSchema
from app.services.alert_service import AlertService
from app.services.audit_service import AuditService

router = APIRouter(prefix="/alerts", tags=["Alert Management"])


@router.get(
    "/statistics",
    response_model=ResponseSchema[AlertStatisticsOut],
    summary="Get overall alert queue statistics and severity breakdown",
)
def get_alert_statistics(
    _current_user: User = Depends(get_current_active_user),
    alert_service: AlertService = Depends(get_alert_service),
) -> ResponseSchema:
    stats = alert_service.get_statistics()
    return ResponseSchema(success=True, data=stats)


@router.post(
    "/auto-generate",
    response_model=ResponseSchema[AutoGenerateAlertsResponse],
    summary="Auto-generate alerts for all unalerted risk assessments",
)
def auto_generate_alerts(
    _current_user: User = Depends(get_current_active_user),
    alert_service: AlertService = Depends(get_alert_service),
) -> ResponseSchema:
    resp = alert_service.auto_generate_alerts()
    return ResponseSchema(success=True, message=resp.message, data=resp)


@router.get(
    "",
    response_model=PaginatedResponseSchema[AlertOut],
    summary="List, search, and filter security alerts",
)
def list_alerts(
    status: Optional[AlertStatus] = Query(default=None, description="Filter by status (open, in_progress, resolved, etc.)"),
    severity: Optional[RiskLevel] = Query(default=None, description="Filter by severity (low, medium, high, critical)"),
    assigned_to_id: Optional[uuid.UUID] = Query(default=None, description="Filter by assigned analyst UUID"),
    incident_id: Optional[uuid.UUID] = Query(default=None, description="Filter by parent incident UUID"),
    search: Optional[str] = Query(default=None, description="Search keyword in title or description"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    _current_user: User = Depends(get_current_active_user),
    alert_service: AlertService = Depends(get_alert_service),
) -> PaginatedResponseSchema:
    items, total = alert_service.list_alerts(
        status=status,
        severity=severity,
        assigned_to_id=assigned_to_id,
        incident_id=incident_id,
        search_query=search,
        skip=skip,
        limit=limit,
    )
    return PaginatedResponseSchema(
        success=True,
        data=items,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.post(
    "",
    response_model=ResponseSchema[AlertOut],
    status_code=status.HTTP_201_CREATED,
    summary="Create a new SOC alert manually",
)
def create_alert(
    data: AlertCreate,
    _current_user: User = Depends(get_current_active_user),
    alert_service: AlertService = Depends(get_alert_service),
) -> ResponseSchema:
    alert = alert_service.create_alert(data)
    return ResponseSchema(success=True, message="Alert created successfully.", data=alert)


@router.get(
    "/{alert_id}",
    response_model=ResponseSchema[AlertOut],
    summary="Get alert details by ID",
)
def get_alert(
    alert_id: uuid.UUID,
    _current_user: User = Depends(get_current_active_user),
    alert_service: AlertService = Depends(get_alert_service),
) -> ResponseSchema:
    alert = alert_service.get_alert_by_id(alert_id)
    return ResponseSchema(success=True, data=alert)


@router.patch(
    "/{alert_id}/status",
    response_model=ResponseSchema[AlertOut],
    summary="Update alert lifecycle status (OPEN -> IN_PROGRESS -> RESOLVED/CLOSED)",
)
def update_alert_status(
    alert_id: uuid.UUID,
    data: AlertStatusUpdate,
    current_user: User = Depends(get_current_active_user),
    alert_service: AlertService = Depends(get_alert_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> ResponseSchema:
    updated = alert_service.update_status(alert_id, data.status)
    audit_service.log(
        action="ALERT_STATUS_UPDATE",
        user=current_user,
        object_type="ALERT",
        object_id=str(alert_id),
        details={"status": data.status.value if hasattr(data.status, "value") else str(data.status), "title": updated.title},
    )
    return ResponseSchema(success=True, message="Alert status updated.", data=updated)


@router.patch(
    "/{alert_id}/assign",
    response_model=ResponseSchema[AlertOut],
    summary="Assign or reassign alert to a SOC analyst",
)
def assign_alert(
    alert_id: uuid.UUID,
    data: AlertAssignRequest,
    _current_user: User = Depends(get_current_active_user),
    alert_service: AlertService = Depends(get_alert_service),
) -> ResponseSchema:
    updated = alert_service.assign_alert(alert_id, data.user_id)
    return ResponseSchema(success=True, message="Alert assignment updated.", data=updated)
