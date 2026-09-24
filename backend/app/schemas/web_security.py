"""Web Security Pydantic schemas for request validation and response serialization."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.models.enums import RiskLevel
from app.schemas.base import BaseSchema


class AllowlistCreateRequest(BaseSchema):
    pattern: str
    description: Optional[str] = None
    is_active: bool = True


class AllowlistUpdateRequest(BaseSchema):
    pattern: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None


class AllowlistEntryOut(BaseSchema):
    id: uuid.UUID
    pattern: str
    description: Optional[str] = None
    is_active: bool
    created_by_username: Optional[str] = None
    created_at: datetime


class ScanLaunchRequest(BaseSchema):
    target_url: str
    scan_profile: str = "standard"  # quick, standard, deep, headers_only
    max_requests: int = 50
    timeout_seconds: int = 15


class WebSecurityFindingOut(BaseSchema):
    id: uuid.UUID
    scan_id: uuid.UUID
    finding_id: str
    title: str
    category: str
    severity: RiskLevel
    confidence: float
    status: str
    endpoint: str
    http_method: str
    parameter: Optional[str] = None
    evidence: str
    description: str
    remediation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    affected_component: Optional[str] = None
    discovered_at: datetime
    risk_score: float
    related_alert_id: Optional[uuid.UUID] = None
    related_incident_id: Optional[uuid.UUID] = None
    analyst_notes: Optional[str] = None


class WebSecurityScanOut(BaseSchema):
    id: uuid.UUID
    scan_id: str
    target_url: str
    target_host: str
    resolved_ip: Optional[str] = None
    scan_profile: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[float] = None
    pages_checked: int
    endpoints_checked: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    informational_count: int = 0
    posture_score: float
    posture_breakdown: Optional[Dict[str, Any]] = None
    exposed_services: Optional[List[Dict[str, Any]]] = None
    initiated_by_username: Optional[str] = None
    error_message: Optional[str] = None
    findings: Optional[List[WebSecurityFindingOut]] = None


class PostureScoreOut(BaseSchema):
    posture_score: float
    target_host: Optional[str] = None
    scan_id: Optional[str] = None
    evaluated_at: datetime
    breakdown: Dict[str, float]
    active_findings: int
    critical_findings: int
    targets_monitored: int


class ScanComparisonOut(BaseSchema):
    target_host: str
    current_scan_id: str
    previous_scan_id: Optional[str] = None
    current_score: float
    previous_score: Optional[float] = None
    score_improvement: float
    new_findings: List[WebSecurityFindingOut]
    resolved_findings_count: int
    still_open_count: int


class TopVulnerableEndpointOut(BaseSchema):
    endpoint: str
    findings_count: int
    severity: str
