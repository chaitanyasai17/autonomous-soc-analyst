"""
Evidence Timeline API endpoint — Unified chronological forensic investigation timeline.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_evidence_timeline_service
from app.models.user import User
from app.schemas.base import ResponseSchema
from app.schemas.timeline import TimelineResponse
from app.services.evidence_timeline_service import EvidenceTimelineService

router = APIRouter(prefix="/timeline", tags=["Evidence Timeline"])


@router.get(
    "",
    response_model=ResponseSchema[TimelineResponse],
    summary="Get unified chronological forensic evidence timeline",
)
def get_timeline(
    endpoint_id: Optional[uuid.UUID] = Query(None, description="Filter by Endpoint ID"),
    incident_id: Optional[uuid.UUID] = Query(None, description="Filter by Incident ID"),
    alert_id: Optional[uuid.UUID] = Query(None, description="Filter by Alert ID"),
    detection_id: Optional[uuid.UUID] = Query(None, description="Filter by Detection ID"),
    start_date: Optional[datetime] = Query(None, description="Start timestamp filter"),
    end_date: Optional[datetime] = Query(None, description="End timestamp filter"),
    limit: int = Query(150, ge=1, le=500, description="Max entries to return"),
    current_user: User = Depends(get_current_active_user),
    service: EvidenceTimelineService = Depends(get_evidence_timeline_service),
) -> ResponseSchema[TimelineResponse]:
    result = service.build_timeline(
        endpoint_id=endpoint_id,
        incident_id=incident_id,
        alert_id=alert_id,
        detection_id=detection_id,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
    )
    return ResponseSchema(success=True, data=result)
