"""
Dashboard summary endpoint — consolidates SOC KPIs, threat trends, and metrics for executive dashboard.
"""

from typing import Any, Dict, List

from fastapi import APIRouter, Depends

from app.dependencies.auth import get_current_active_user
from app.dependencies.services import (
    get_alert_service,
    get_detection_service,
    get_endpoint_service,
    get_incident_service,
    get_mitre_service,
    get_risk_service,
    get_upload_service,
    get_web_security_service,
)
from app.models.user import User
from app.schemas.alert import AlertOut
from app.schemas.base import BaseSchema, ResponseSchema
from app.schemas.mitre import MitreTacticOut
from app.schemas.web_security import TopVulnerableEndpointOut
from app.services.alert_service import AlertService
from app.services.detection_service import DetectionService
from app.services.endpoint_service import EndpointService
from app.services.incident_service import IncidentService
from app.services.mitre_service import MitreService
from app.services.risk_service import RiskService
from app.services.upload_service import UploadService
from app.services.web_security_service import WebSecurityService

router = APIRouter(prefix="/dashboard", tags=["SOC Dashboard"])


class DashboardSummary(BaseSchema):
    total_alerts: int
    critical_alerts: int
    open_incidents: int
    average_risk_score: float
    total_logs_uploaded: int
    severity_distribution: Dict[str, int]
    incident_status_distribution: Dict[str, int]
    recent_alerts: List[AlertOut]
    top_tactics: List[MitreTacticOut]
    web_posture_score: float = 100.0
    active_web_findings: int = 0
    targets_monitored: int = 0
    top_vulnerable_endpoints: List[TopVulnerableEndpointOut] = []
    total_detections: int = 0
    active_alerts: int = 0
    at_risk_endpoints: int = 0
    total_endpoints: int = 0
    online_endpoints: int = 0


@router.get(
    "/summary",
    response_model=ResponseSchema[DashboardSummary],
    summary="Get aggregated SOC executive dashboard metrics",
)
def get_dashboard_summary(
    current_user: User = Depends(get_current_active_user),
    alert_service: AlertService = Depends(get_alert_service),
    incident_service: IncidentService = Depends(get_incident_service),
    risk_service: RiskService = Depends(get_risk_service),
    mitre_service: MitreService = Depends(get_mitre_service),
    upload_service: UploadService = Depends(get_upload_service),
    web_security_service: WebSecurityService = Depends(get_web_security_service),
    detection_service: DetectionService = Depends(get_detection_service),
    endpoint_service: EndpointService = Depends(get_endpoint_service),
) -> ResponseSchema:
    alert_stats = alert_service.get_statistics()
    incident_stats = incident_service.get_statistics()
    risk_stats = risk_service.get_statistics()
    tactics = mitre_service.get_tactics()
    recent_alerts, _ = alert_service.list_alerts(limit=6)
    _, total_logs = upload_service.list_uploads(requesting_user=current_user, limit=1)

    posture = web_security_service.get_posture_summary()
    top_endpoints = web_security_service.get_top_vulnerable_endpoints(limit=5)
    det_stats = detection_service.get_statistics(current_user)
    ep_stats = endpoint_service.get_statistics(current_user)
    open_alerts_count = alert_stats.by_status.get("open", 0) + alert_stats.by_status.get("in_progress", 0)
    at_risk = (
        ep_stats.by_risk_level.get("critical", 0)
        + ep_stats.by_risk_level.get("high", 0)
        + ep_stats.by_risk_level.get("medium", 0)
    )

    summary_data = DashboardSummary(
        total_alerts=alert_stats.total_alerts,
        critical_alerts=alert_stats.critical_open,
        open_incidents=incident_stats.open_active_incidents,
        average_risk_score=risk_stats.average_risk_score,
        total_logs_uploaded=total_logs,
        severity_distribution=alert_stats.by_severity,
        incident_status_distribution=incident_stats.by_status,
        recent_alerts=recent_alerts,
        top_tactics=tactics,
        web_posture_score=posture.posture_score,
        active_web_findings=posture.active_findings,
        targets_monitored=posture.targets_monitored,
        top_vulnerable_endpoints=top_endpoints,
        total_detections=det_stats.total_detections,
        active_alerts=open_alerts_count,
        at_risk_endpoints=at_risk,
        total_endpoints=ep_stats.total_endpoints,
        online_endpoints=ep_stats.online_endpoints,
    )

    return ResponseSchema(success=True, data=summary_data)

