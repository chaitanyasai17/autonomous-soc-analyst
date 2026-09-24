"""SOC Health and Diagnostics Pydantic schemas (Part 16)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from app.schemas.base import BaseSchema


class ComponentHealth(BaseSchema):
    name: str
    status: str  # HEALTHY, DEGRADED, ERROR
    latency_ms: float
    message: str
    last_check: datetime


class SOCHealthReportOut(BaseSchema):
    overall_status: str  # HEALTHY, DEGRADED, ERROR
    timestamp: datetime
    active_components: int
    total_components: int
    components: Dict[str, ComponentHealth]
    operational_metrics: Optional[Dict[str, Any]] = None
