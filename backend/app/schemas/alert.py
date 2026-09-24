"""
Alert Pydantic schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Dict, List, Optional

from app.models.enums import AlertStatus, RiskLevel
from app.schemas.base import BaseSchema


class AlertCreate(BaseSchema):
    title: str
    description: Optional[str] = None
    severity: RiskLevel
    risk_assessment_id: Optional[uuid.UUID] = None
    incident_id: Optional[uuid.UUID] = None
    assigned_to_id: Optional[uuid.UUID] = None
    web_finding_id: Optional[uuid.UUID] = None


class AlertUpdate(BaseSchema):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[RiskLevel] = None
    status: Optional[AlertStatus] = None
    assigned_to_id: Optional[uuid.UUID] = None
    incident_id: Optional[uuid.UUID] = None
    web_finding_id: Optional[uuid.UUID] = None


class AlertStatusUpdate(BaseSchema):
    status: AlertStatus


class AlertAssignRequest(BaseSchema):
    user_id: Optional[uuid.UUID] = None


class AlertOut(BaseSchema):
    id: uuid.UUID
    title: str
    description: Optional[str] = None
    severity: RiskLevel
    status: AlertStatus
    resolved_at: Optional[datetime] = None
    risk_assessment_id: Optional[uuid.UUID] = None
    incident_id: Optional[uuid.UUID] = None
    assigned_to_id: Optional[uuid.UUID] = None
    created_at: datetime
    risk_score: Optional[float] = None
    assigned_username: Optional[str] = None
    web_finding_id: Optional[uuid.UUID] = None


class AlertStatisticsOut(BaseSchema):
    total_alerts: int
    critical_open: int
    by_severity: Dict[str, int]
    by_status: Dict[str, int]


class AutoGenerateAlertsResponse(BaseSchema):
    alerts_created: int
    message: str
