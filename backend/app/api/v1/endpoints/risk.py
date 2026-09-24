"""
Risk Scoring endpoints — evaluate detection risk scores, explainability, and risk distribution stats.
"""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_risk_service
from app.models.enums import RiskLevel
from app.models.user import User
from app.schemas.base import PaginatedResponseSchema, ResponseSchema
from app.schemas.risk import (
    BatchRiskAssessmentOut,
    RiskAssessmentOut,
    RiskExplanationOut,
    RiskStatisticsOut,
)
from app.services.risk_service import RiskService

router = APIRouter(prefix="/risk", tags=["Risk Scoring"])


@router.get(
    "/statistics",
    response_model=ResponseSchema[RiskStatisticsOut],
    summary="Get overall risk distribution statistics",
)
def get_risk_statistics(
    _current_user: User = Depends(get_current_active_user),
    risk_service: RiskService = Depends(get_risk_service),
) -> ResponseSchema:
    stats = risk_service.get_statistics()
    return ResponseSchema(success=True, data=stats)


@router.post(
    "/assess/{detection_id}",
    response_model=ResponseSchema[RiskAssessmentOut],
    summary="Calculate deterministic risk score and breakdown for a Sigma detection",
)
def assess_detection(
    detection_id: uuid.UUID,
    _current_user: User = Depends(get_current_active_user),
    risk_service: RiskService = Depends(get_risk_service),
) -> ResponseSchema:
    result = risk_service.assess_detection(detection_id)
    return ResponseSchema(
        success=True,
        message=f"Risk assessed: {result.risk_level.value.upper()} (Score: {result.risk_score})",
        data=result,
    )


@router.post(
    "/assess-batch",
    response_model=ResponseSchema[BatchRiskAssessmentOut],
    summary="Batch calculate risk scores for all unassessed detections",
)
def assess_all_unassessed(
    _current_user: User = Depends(get_current_active_user),
    risk_service: RiskService = Depends(get_risk_service),
) -> ResponseSchema:
    batch_res = risk_service.assess_all_unassessed()
    return ResponseSchema(
        success=True,
        message=f"Batch evaluation complete. {batch_res.assessed_count} detection(s) assessed.",
        data=batch_res,
    )


@router.get(
    "/assessments",
    response_model=PaginatedResponseSchema[RiskAssessmentOut],
    summary="List risk assessments with filtering and pagination",
)
def list_assessments(
    risk_level: Optional[RiskLevel] = Query(default=None, description="Filter by risk level"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    _current_user: User = Depends(get_current_active_user),
    risk_service: RiskService = Depends(get_risk_service),
) -> PaginatedResponseSchema:
    items, total = risk_service.list_assessments(
        risk_level=risk_level, skip=skip, limit=limit
    )
    return PaginatedResponseSchema(
        success=True,
        data=items,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/explain/{assessment_id}",
    response_model=ResponseSchema[RiskExplanationOut],
    summary="Get transparent, mathematical explanation of calculated risk score",
)
def explain_risk(
    assessment_id: uuid.UUID,
    _current_user: User = Depends(get_current_active_user),
    risk_service: RiskService = Depends(get_risk_service),
) -> ResponseSchema:
    explanation = risk_service.explain_risk(assessment_id)
    return ResponseSchema(success=True, data=explanation)

