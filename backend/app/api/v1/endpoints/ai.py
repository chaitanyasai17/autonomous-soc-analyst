"""
AI Threat Analysis endpoints — trigger AI threat intelligence on detections, alerts, and incidents.
"""

import uuid

from fastapi import APIRouter, Depends

from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_ai_service
from app.models.user import User
from app.schemas.ai import AIProviderStatus, AIThreatAnalysisResponse
from app.schemas.base import ResponseSchema
from app.services.ai_service import AIService

router = APIRouter(prefix="/ai", tags=["AI Threat Analysis"])


@router.get(
    "/status",
    response_model=ResponseSchema[AIProviderStatus],
    summary="Get status of AI Threat Analysis engine and active provider",
)
def get_ai_status(
    _current_user: User = Depends(get_current_active_user),
    ai_service: AIService = Depends(get_ai_service),
) -> ResponseSchema:
    status_info = ai_service.get_status()
    return ResponseSchema(success=True, data=status_info)


@router.post(
    "/analyze/detection/{detection_id}",
    response_model=ResponseSchema[AIThreatAnalysisResponse],
    summary="Run AI threat analysis and enrichment on a Sigma detection",
)
async def analyze_detection(
    detection_id: uuid.UUID,
    _current_user: User = Depends(get_current_active_user),
    ai_service: AIService = Depends(get_ai_service),
) -> ResponseSchema:
    analysis = await ai_service.analyze_detection(detection_id)
    return ResponseSchema(
        success=True,
        message="AI threat assessment completed successfully.",
        data=analysis,
    )


@router.post(
    "/analyze/alert/{alert_id}",
    response_model=ResponseSchema[AIThreatAnalysisResponse],
    summary="Run AI threat analysis and investigation enrichment specifically on a single Alert",
)
async def analyze_alert(
    alert_id: uuid.UUID,
    _current_user: User = Depends(get_current_active_user),
    ai_service: AIService = Depends(get_ai_service),
) -> ResponseSchema:
    analysis = await ai_service.analyze_alert(alert_id)
    return ResponseSchema(
        success=True,
        message="AI threat assessment for alert completed successfully.",
        data=analysis,
    )


@router.post(
    "/analyze/incident/{incident_id}",
    response_model=ResponseSchema[AIThreatAnalysisResponse],
    summary="Run consolidated AI threat analysis and response playbook synthesis on an Incident",
)
async def analyze_incident(
    incident_id: uuid.UUID,
    _current_user: User = Depends(get_current_active_user),
    ai_service: AIService = Depends(get_ai_service),
) -> ResponseSchema:
    analysis = await ai_service.analyze_incident(incident_id)
    return ResponseSchema(
        success=True,
        message="Consolidated incident AI response playbook synthesized successfully.",
        data=analysis,
    )

