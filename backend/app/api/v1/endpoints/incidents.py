"""
Incident management endpoints — investigations, correlation, lifecycle transitions, and ownership assignment.
"""

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query, status

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_audit_service, get_incident_service
from app.models.enums import IncidentStatus, RiskLevel
from app.models.user import User
from app.schemas.base import PaginatedResponseSchema, ResponseSchema
from app.schemas.incident import (
    AutoCorrelateResponse,
    IncidentAssignRequest,
    IncidentCreate,
    IncidentLinkAlertsRequest,
    IncidentOut,
    IncidentStatisticsOut,
    IncidentStatusUpdate,
    IncidentTimelineOut,
)
from app.services.audit_service import AuditService
from app.services.incident_service import IncidentService

router = APIRouter(prefix="/incidents", tags=["Incident Management"])


@router.get(
    "/statistics",
    response_model=ResponseSchema[IncidentStatisticsOut],
    summary="Get overall incident metrics and lifecycle distribution",
)
def get_incident_statistics(
    _current_user: User = Depends(get_current_active_user),
    incident_service: IncidentService = Depends(get_incident_service),
) -> ResponseSchema:
    stats = incident_service.get_statistics()
    return ResponseSchema(success=True, data=stats)


@router.post(
    "/auto-correlate",
    response_model=ResponseSchema[AutoCorrelateResponse],
    summary="Run automated alert correlation to group unlinked alerts into incidents",
)
def auto_correlate(
    _current_user: User = Depends(get_current_active_user),
    incident_service: IncidentService = Depends(get_incident_service),
) -> ResponseSchema:
    resp = incident_service.auto_correlate()
    return ResponseSchema(success=True, message=resp.message, data=resp)


@router.get(
    "",
    response_model=PaginatedResponseSchema[IncidentOut],
    summary="List, search, and filter SOC incidents",
)
def list_incidents(
    status: Optional[IncidentStatus] = Query(default=None, description="Filter by status (open, investigating, contained, resolved, closed)"),
    priority: Optional[RiskLevel] = Query(default=None, description="Filter by priority (low, medium, high, critical)"),
    owner_id: Optional[uuid.UUID] = Query(default=None, description="Filter by owner UUID"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    _current_user: User = Depends(get_current_active_user),
    incident_service: IncidentService = Depends(get_incident_service),
) -> PaginatedResponseSchema:
    items, total = incident_service.list_incidents(
        status=status,
        priority=priority,
        owner_id=owner_id,
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
    response_model=ResponseSchema[IncidentOut],
    status_code=status.HTTP_201_CREATED,
    summary="Create a new SOC investigation incident",
)
def create_incident(
    data: IncidentCreate,
    _current_user: User = Depends(get_current_active_user),
    incident_service: IncidentService = Depends(get_incident_service),
) -> ResponseSchema:
    incident = incident_service.create_incident(data)
    return ResponseSchema(success=True, message="Incident created.", data=incident)


@router.get(
    "/{incident_id}",
    response_model=ResponseSchema[IncidentOut],
    summary="Get incident details with timeline and linked alerts",
)
def get_incident(
    incident_id: uuid.UUID,
    _current_user: User = Depends(get_current_active_user),
    incident_service: IncidentService = Depends(get_incident_service),
) -> ResponseSchema:
    incident = incident_service.get_incident_or_404(incident_id)
    return ResponseSchema(success=True, data=incident)


@router.patch(
    "/{incident_id}/status",
    response_model=ResponseSchema[IncidentOut],
    summary="Transition incident investigation status",
)
def update_incident_status(
    incident_id: uuid.UUID,
    data: IncidentStatusUpdate,
    current_user: User = Depends(get_current_active_user),
    incident_service: IncidentService = Depends(get_incident_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> ResponseSchema:
    updated = incident_service.update_status(incident_id, data.status)
    audit_service.log(
        action="INCIDENT_STATUS_UPDATE",
        user=current_user,
        object_type="INCIDENT",
        object_id=str(incident_id),
        details={"status": data.status.value if hasattr(data.status, "value") else str(data.status), "incident_number": updated.incident_number},
    )
    return ResponseSchema(success=True, message="Incident status updated.", data=updated)


@router.patch(
    "/{incident_id}/assign",
    response_model=ResponseSchema[IncidentOut],
    summary="Assign or transfer incident lead ownership",
)
def assign_incident_owner(
    incident_id: uuid.UUID,
    data: IncidentAssignRequest,
    _current_user: User = Depends(get_current_active_user),
    incident_service: IncidentService = Depends(get_incident_service),
) -> ResponseSchema:
    updated = incident_service.assign_owner(incident_id, data.user_id)
    return ResponseSchema(success=True, message="Incident owner assigned.", data=updated)


@router.post(
    "/{incident_id}/alerts",
    response_model=ResponseSchema[IncidentOut],
    summary="Link alerts to this incident investigation",
)
def link_alerts_to_incident(
    incident_id: uuid.UUID,
    data: IncidentLinkAlertsRequest,
    _current_user: User = Depends(get_current_active_user),
    incident_service: IncidentService = Depends(get_incident_service),
) -> ResponseSchema:
    updated = incident_service.link_alerts(incident_id, data.alert_ids)
    return ResponseSchema(success=True, message="Alerts linked to incident.", data=updated)


@router.get(
    "/{incident_id}/timeline",
    response_model=ResponseSchema[IncidentTimelineOut],
    summary="Get chronological forensic evidence timeline for an incident",
)
def get_incident_timeline(
    incident_id: uuid.UUID,
    _current_user: User = Depends(get_current_active_user),
    incident_service: IncidentService = Depends(get_incident_service),
) -> ResponseSchema:
    timeline = incident_service.get_timeline(incident_id)
    return ResponseSchema(success=True, data=timeline)

