"""IOC Pydantic schemas (Part 9)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Dict, List, Optional

from app.schemas.base import BaseSchema


class IOCRecordOut(BaseSchema):
    id: uuid.UUID
    ioc_type: str
    value: str
    source: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    related_alert_id: Optional[uuid.UUID] = None
    related_incident_id: Optional[uuid.UUID] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None

    # Relationship counts and classification
    classification: str = "Observed"  # Observed, Suspicious, Confirmed Malicious
    occurrences: int = 1
    risk_level: str = "low"
    related_detections_count: int = 0
    related_alerts_count: int = 0
    related_incidents_count: int = 0


class IOCEventSummary(BaseSchema):
    id: uuid.UUID
    timestamp: datetime
    event_type: str
    source_ip: Optional[str] = None
    hostname: Optional[str] = None
    raw_snippet: Optional[str] = None


class IOCDetectionSummary(BaseSchema):
    id: uuid.UUID
    rule_title: str
    severity: str
    timestamp: datetime
    verdict: Optional[str] = None


class IOCAlertSummary(BaseSchema):
    id: uuid.UUID
    title: str
    severity: str
    status: str
    created_at: datetime


class IOCIncidentSummary(BaseSchema):
    id: uuid.UUID
    incident_number: str
    priority: str
    status: str
    opened_at: datetime


class IOCEndpointSummary(BaseSchema):
    id: uuid.UUID
    hostname: str
    ip_address: Optional[str] = None
    status: str
    risk_level: str


class IOCGraphOut(BaseSchema):
    ioc: IOCRecordOut
    events: List[IOCEventSummary]
    detections: List[IOCDetectionSummary]
    alerts: List[IOCAlertSummary]
    incidents: List[IOCIncidentSummary]
    endpoints: List[IOCEndpointSummary]


class IOCStatisticsOut(BaseSchema):
    total_iocs: int
    by_type: Dict[str, int]
    by_classification: Dict[str, int] = {}
