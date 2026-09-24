"""Endpoint Pydantic schemas for request validation and response serialization."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Dict, List, Optional

from pydantic import Field

from app.models.enums import RiskLevel
from app.schemas.base import BaseSchema


class EndpointCreate(BaseSchema):
    hostname: str = Field(..., min_length=2, max_length=255, description="FQDN or computer hostname")
    ip_address: Optional[str] = Field(None, max_length=45, description="Primary IPv4 or IPv6 address")
    mac_address: Optional[str] = Field(None, max_length=50, description="Hardware MAC address")
    operating_system: str = Field(default="Windows 11 Enterprise", max_length=100)
    os_version: Optional[str] = Field(default="23H2", max_length=50)
    agent_version: str = Field(default="1.4.2-asoc", max_length=50)
    tags: Optional[List[str]] = Field(default_factory=list)


class EndpointUpdate(BaseSchema):
    ip_address: Optional[str] = None
    operating_system: Optional[str] = None
    os_version: Optional[str] = None
    status: Optional[str] = None  # online, offline, degraded
    risk_level: Optional[RiskLevel] = None
    tags: Optional[List[str]] = None


class EndpointIsolateRequest(BaseSchema):
    is_isolated: bool = True
    reason: Optional[str] = Field(None, max_length=255, description="Forensic containment justification")


class EndpointOut(BaseSchema):
    id: uuid.UUID
    hostname: str
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    operating_system: str
    os_version: Optional[str] = None
    agent_version: str
    status: str
    risk_level: RiskLevel
    owner_id: uuid.UUID
    owner_username: Optional[str] = None
    is_isolated: bool
    isolation_reason: Optional[str] = None
    last_seen: datetime
    registered_at: datetime
    tags: Optional[List[str]] = None
    
    # Live database-derived metrics
    event_count: int = 0
    detection_count: int = 0
    alert_count: int = 0


class EndpointTelemetryEvent(BaseSchema):
    id: uuid.UUID
    timestamp: datetime
    event_type: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    username: Optional[str] = None
    severity: RiskLevel
    message: Optional[str] = None


class EndpointDetectionSummary(BaseSchema):
    id: uuid.UUID
    rule_title: str
    severity: RiskLevel
    detection_timestamp: datetime
    verdict: Optional[str] = None


class EndpointAlertSummary(BaseSchema):
    id: uuid.UUID
    title: str
    severity: RiskLevel
    status: str
    created_at: datetime


class EndpointIncidentSummary(BaseSchema):
    id: uuid.UUID
    incident_number: str
    priority: RiskLevel
    status: str
    opened_at: datetime


class EndpointDetailOut(BaseSchema):
    endpoint: EndpointOut
    recent_events: List[EndpointTelemetryEvent]
    detections: List[EndpointDetectionSummary]
    alerts: List[EndpointAlertSummary]
    incidents: List[EndpointIncidentSummary]


class EndpointStatisticsOut(BaseSchema):
    total_endpoints: int
    online_endpoints: int
    offline_endpoints: int
    degraded_endpoints: int
    isolated_endpoints: int
    by_risk_level: Dict[str, int]
