"""
Incident Pydantic schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.models.enums import IncidentStatus, RiskLevel
from app.schemas.alert import AlertOut
from app.schemas.base import BaseSchema


class IncidentCreate(BaseSchema):
    priority: RiskLevel = RiskLevel.HIGH
    owner_id: Optional[uuid.UUID] = None
    alert_ids: Optional[List[uuid.UUID]] = None


class IncidentUpdate(BaseSchema):
    priority: Optional[RiskLevel] = None
    status: Optional[IncidentStatus] = None
    owner_id: Optional[uuid.UUID] = None


class IncidentStatusUpdate(BaseSchema):
    status: IncidentStatus


class IncidentAssignRequest(BaseSchema):
    user_id: Optional[uuid.UUID] = None


class IncidentLinkAlertsRequest(BaseSchema):
    alert_ids: List[uuid.UUID]


class IncidentOut(BaseSchema):
    id: uuid.UUID
    incident_number: str
    priority: RiskLevel
    status: IncidentStatus
    opened_at: datetime
    closed_at: Optional[datetime] = None
    owner_id: Optional[uuid.UUID] = None
    owner_username: Optional[str] = None
    alert_count: int = 0
    alerts: List[AlertOut] = []


class IncidentStatisticsOut(BaseSchema):
    total_incidents: int
    open_active_incidents: int
    by_status: Dict[str, int]
    by_priority: Dict[str, int]


class AutoCorrelateResponse(BaseSchema):
    incidents_created: int
    alerts_grouped: int
    message: str


class IncidentTimelineEventOut(BaseSchema):
    event_id: str
    timestamp: datetime
    event_type: str
    title: str
    description: str
    severity: Optional[str] = None
    source: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class IncidentTimelineOut(BaseSchema):
    incident_id: uuid.UUID
    incident_number: str
    total_events: int
    events: List[IncidentTimelineEventOut] = []
