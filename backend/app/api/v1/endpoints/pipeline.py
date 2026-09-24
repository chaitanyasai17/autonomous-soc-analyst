"""
Pipeline trace endpoint — Full end-to-end provenance graph traversal.
"""

import uuid
from typing import Any, Dict

from fastapi import APIRouter, Depends

from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_pipeline_trace_service
from app.models.user import User
from app.schemas.base import ResponseSchema
from app.services.pipeline_trace_service import PipelineTraceService

router = APIRouter(prefix="/pipeline", tags=["Pipeline Trace"])


@router.get(
    "/trace/{object_type}/{object_id}",
    response_model=ResponseSchema[Dict[str, Any]],
    summary="Trace complete end-to-end SOC pipeline provenance for an object",
)
def get_pipeline_trace(
    object_type: str,
    object_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    trace_service: PipelineTraceService = Depends(get_pipeline_trace_service),
) -> ResponseSchema:
    result = trace_service.trace(object_type=object_type, object_id=object_id)
    return ResponseSchema(success=True, data=result)
