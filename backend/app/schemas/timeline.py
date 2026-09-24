"""Timeline Pydantic schemas for chronological forensic investigation."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.schemas.base import BaseSchema


class TimelineEntry(BaseSchema):
    id: str
    timestamp: datetime
    stage: str  # INGESTION, NORMALIZATION, DETECTION, MITRE, RISK, ALERT, CORRELATION, INCIDENT, CONTAINMENT
    event_type: str
    source: str
    object_id: str
    severity: str  # low, medium, high, critical, info
    description: str
    related_endpoint: Optional[str] = None
    related_alert: Optional[str] = None
    related_detection: Optional[str] = None
    related_incident: Optional[str] = None
    details: Dict[str, Any] = {}


class TimelineResponse(BaseSchema):
    total_events: int
    filter_applied: Dict[str, Any]
    timeline: List[TimelineEntry]
