"""Endpoint Service — manages endpoint lifecycle, host isolation, and telemetry correlation."""

from __future__ import annotations

import logging
import uuid
from typing import Any, List, Optional, Tuple

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.exceptions import ConflictError, NotFoundError, PermissionDeniedError
from app.models.alert import Alert
from app.models.endpoint import Endpoint
from app.models.enums import RiskLevel, UserRole
from app.models.incident import Incident
from app.models.parsed_log import ParsedLog
from app.models.risk_assessment import RiskAssessment
from app.models.sigma_detection import SigmaDetection
from app.models.user import User
from app.repositories.endpoint_repository import EndpointRepository
from app.schemas.endpoint import (
    EndpointAlertSummary,
    EndpointCreate,
    EndpointDetailOut,
    EndpointDetectionSummary,
    EndpointIncidentSummary,
    EndpointIsolateRequest,
    EndpointOut,
    EndpointStatisticsOut,
    EndpointTelemetryEvent,
    EndpointUpdate,
)
from app.services.audit_service import AuditService
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)


class EndpointService:
    def __init__(
        self,
        endpoint_repo: EndpointRepository,
        db_session: Session,
        audit_service: AuditService | None = None,
    ):
        self.repo = endpoint_repo
        self.db = db_session
        self.audit = audit_service

    def _has_global_access(self, user: User) -> bool:
        role_val = user.role.value if hasattr(user.role, "value") else str(user.role)
        return role_val in (UserRole.SUPER_ADMIN.value, UserRole.ADMIN.value, UserRole.SOC_MANAGER.value)

    def auto_discover_from_telemetry(self, default_owner: User) -> int:
        """Auto-enroll unique hosts observed in ParsedLog telemetry if not already present."""
        hosts = self.db.execute(
            select(ParsedLog.hostname, ParsedLog.source_ip)
            .where(ParsedLog.hostname.is_not(None))
            .distinct()
        ).all()

        created_count = 0
        for hostname, ip in hosts:
            if not hostname or hostname in ("unknown", "N/A", "none"):
                continue
            existing = self.repo.get_by_hostname(hostname)
            if not existing:
                endpoint = Endpoint(
                    id=uuid.uuid4(),
                    hostname=hostname,
                    ip_address=ip or "127.0.0.1",
                    operating_system="Windows Server 2022" if "server" in hostname.lower() else "Windows 11 Enterprise",
                    agent_version="1.4.2-asoc",
                    status="online",
                    risk_level=RiskLevel.LOW,
                    owner_id=default_owner.id,
                    is_isolated=False,
                    last_seen=utc_now(),
                    registered_at=utc_now(),
                    tags=["auto-enrolled", "telemetry-source"],
                )
                self.repo.create(endpoint)
                created_count += 1

        if created_count > 0:
            self.db.commit()
        return created_count

    def list_endpoints(
        self,
        current_user: User,
        status: Optional[str] = None,
        risk_level: Optional[RiskLevel] = None,
        search_query: Optional[str] = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[List[EndpointOut], int]:
        # Enforce Ownership Isolation in Backend
        owner_filter = None if self._has_global_access(current_user) else current_user.id

        # If zero endpoints in the system, discover from telemetry
        total_in_db = self.db.execute(select(func.count(Endpoint.id))).scalar_one()
        if total_in_db == 0:
            self.auto_discover_from_telemetry(current_user)

        endpoints, total = self.repo.search(
            owner_id=owner_filter,
            status=status,
            risk_level=risk_level,
            search_query=search_query,
            skip=skip,
            limit=limit,
        )

        results: List[EndpointOut] = []
        for ep in endpoints:
            counts = self._compute_counts(ep)
            # Update dynamic risk level based on findings
            computed_risk = self._compute_risk_level(counts["critical_alerts"], counts["high_alerts"], counts["detections"])
            if ep.risk_level != computed_risk:
                ep.risk_level = computed_risk
                self.db.add(ep)

            out = EndpointOut(
                id=ep.id,
                hostname=ep.hostname,
                ip_address=ep.ip_address,
                mac_address=ep.mac_address,
                operating_system=ep.operating_system,
                os_version=ep.os_version,
                agent_version=ep.agent_version,
                status=ep.status,
                risk_level=ep.risk_level,
                owner_id=ep.owner_id,
                owner_username=ep.owner.username if ep.owner else "system",
                is_isolated=ep.is_isolated,
                isolation_reason=ep.isolation_reason,
                last_seen=ep.last_seen,
                registered_at=ep.registered_at,
                tags=ep.tags or [],
                event_count=counts["events"],
                detection_count=counts["detections"],
                alert_count=counts["alerts"],
            )
            results.append(out)

        self.db.commit()
        return results, total

    def get_statistics(self, current_user: User) -> EndpointStatisticsOut:
        owner_filter = None if self._has_global_access(current_user) else current_user.id
        stats = self.repo.count_statistics(owner_filter)
        return EndpointStatisticsOut(**stats)

    def get_endpoint_detail(self, endpoint_id: uuid.UUID, current_user: User) -> EndpointDetailOut:
        ep = self.repo.get_with_owner(endpoint_id)
        if not ep:
            raise NotFoundError(f"Endpoint with ID '{endpoint_id}' not found.")

        # Backend Ownership Check
        if not self._has_global_access(current_user) and ep.owner_id != current_user.id:
            raise PermissionDeniedError("Access denied: You do not own this endpoint.")

        counts = self._compute_counts(ep)

        # 1. Recent Events
        host_cond = or_(ParsedLog.hostname == ep.hostname, ParsedLog.source_ip == ep.ip_address)
        events_stmt = (
            select(ParsedLog)
            .where(host_cond)
            .order_by(ParsedLog.timestamp.desc())
            .limit(50)
        )
        events = self.db.execute(events_stmt).scalars().all()
        recent_events = [
            EndpointTelemetryEvent(
                id=ev.id,
                timestamp=ev.timestamp,
                event_type=ev.event_type,
                source_ip=ev.source_ip,
                destination_ip=ev.destination_ip,
                username=ev.username,
                severity=ev.severity,
                message=ev.raw_log[:200] if ev.raw_log else None,
            )
            for ev in events
        ]

        # 2. Detections
        det_stmt = (
            select(SigmaDetection)
            .join(ParsedLog, SigmaDetection.parsed_log_id == ParsedLog.id)
            .where(host_cond)
            .order_by(SigmaDetection.detection_timestamp.desc())
            .limit(50)
        )
        detections = self.db.execute(det_stmt).scalars().all()
        recent_detections = [
            EndpointDetectionSummary(
                id=d.id,
                rule_title=d.rule_title,
                severity=d.severity,
                detection_timestamp=d.detection_timestamp,
                verdict=d.analyst_verdict,
            )
            for d in detections
        ]

        # 3. Alerts
        alert_stmt = (
            select(Alert)
            .join(RiskAssessment, Alert.risk_assessment_id == RiskAssessment.id)
            .join(SigmaDetection, RiskAssessment.sigma_detection_id == SigmaDetection.id)
            .join(ParsedLog, SigmaDetection.parsed_log_id == ParsedLog.id)
            .where(host_cond)
            .order_by(Alert.created_at.desc())
            .limit(50)
        )
        alerts = self.db.execute(alert_stmt).scalars().all()
        recent_alerts = [
            EndpointAlertSummary(
                id=a.id,
                title=a.title,
                severity=a.severity,
                status=a.status.value if hasattr(a.status, "value") else str(a.status),
                created_at=a.created_at,
            )
            for a in alerts
        ]

        # 4. Incidents
        incident_ids = {a.incident_id for a in alerts if a.incident_id}
        recent_incidents: List[EndpointIncidentSummary] = []
        if incident_ids:
            inc_stmt = select(Incident).where(Incident.id.in_(incident_ids)).order_by(Incident.opened_at.desc())
            incidents = self.db.execute(inc_stmt).scalars().all()
            recent_incidents = [
                EndpointIncidentSummary(
                    id=inc.id,
                    incident_number=inc.incident_number,
                    priority=inc.priority,
                    status=inc.status.value if hasattr(inc.status, "value") else str(inc.status),
                    opened_at=inc.opened_at,
                )
                for inc in incidents
            ]

        endpoint_out = EndpointOut(
            id=ep.id,
            hostname=ep.hostname,
            ip_address=ep.ip_address,
            mac_address=ep.mac_address,
            operating_system=ep.operating_system,
            os_version=ep.os_version,
            agent_version=ep.agent_version,
            status=ep.status,
            risk_level=ep.risk_level,
            owner_id=ep.owner_id,
            owner_username=ep.owner.username if ep.owner else "system",
            is_isolated=ep.is_isolated,
            isolation_reason=ep.isolation_reason,
            last_seen=ep.last_seen,
            registered_at=ep.registered_at,
            tags=ep.tags or [],
            event_count=counts["events"],
            detection_count=counts["detections"],
            alert_count=counts["alerts"],
        )

        return EndpointDetailOut(
            endpoint=endpoint_out,
            recent_events=recent_events,
            detections=recent_detections,
            alerts=recent_alerts,
            incidents=recent_incidents,
        )

    def register_endpoint(self, data: EndpointCreate, current_user: User) -> EndpointOut:
        existing = self.repo.get_by_hostname(data.hostname)
        if existing:
            raise ConflictError(f"Endpoint with hostname '{data.hostname}' is already registered.")

        endpoint = Endpoint(
            id=uuid.uuid4(),
            hostname=data.hostname.strip(),
            ip_address=data.ip_address.strip() if data.ip_address else None,
            mac_address=data.mac_address.strip() if data.mac_address else None,
            operating_system=data.operating_system,
            os_version=data.os_version,
            agent_version=data.agent_version,
            status="online",
            risk_level=RiskLevel.LOW,
            owner_id=current_user.id,
            is_isolated=False,
            last_seen=utc_now(),
            registered_at=utc_now(),
            tags=data.tags or ["enrolled"],
        )
        self.repo.create(endpoint)

        if self.audit:
            self.audit.log(
                action="ENDPOINT_REGISTERED",
                user=current_user,
                object_type="ENDPOINT",
                object_id=str(endpoint.id),
                details={"hostname": endpoint.hostname, "ip_address": endpoint.ip_address},
            )

        counts = self._compute_counts(endpoint)
        return EndpointOut(
            id=endpoint.id,
            hostname=endpoint.hostname,
            ip_address=endpoint.ip_address,
            mac_address=endpoint.mac_address,
            operating_system=endpoint.operating_system,
            os_version=endpoint.os_version,
            agent_version=endpoint.agent_version,
            status=endpoint.status,
            risk_level=endpoint.risk_level,
            owner_id=endpoint.owner_id,
            owner_username=current_user.username,
            is_isolated=endpoint.is_isolated,
            isolation_reason=endpoint.isolation_reason,
            last_seen=endpoint.last_seen,
            registered_at=endpoint.registered_at,
            tags=endpoint.tags or [],
            event_count=counts["events"],
            detection_count=counts["detections"],
            alert_count=counts["alerts"],
        )

    def set_isolation(
        self,
        endpoint_id: uuid.UUID,
        req: EndpointIsolateRequest,
        current_user: User,
    ) -> EndpointOut:
        ep = self.repo.get_with_owner(endpoint_id)
        if not ep:
            raise NotFoundError(f"Endpoint with ID '{endpoint_id}' not found.")

        if not self._has_global_access(current_user) and ep.owner_id != current_user.id:
            raise PermissionDeniedError("Access denied: You cannot isolate another user's endpoint.")

        ep.is_isolated = req.is_isolated
        ep.isolation_reason = req.reason if req.is_isolated else None
        self.repo.update(ep)

        action = "ENDPOINT_ISOLATED" if req.is_isolated else "ENDPOINT_RECONNECTED"
        if self.audit:
            self.audit.log(
                action=action,
                user=current_user,
                object_type="ENDPOINT",
                object_id=str(ep.id),
                details={"hostname": ep.hostname, "reason": req.reason},
            )

        counts = self._compute_counts(ep)
        return EndpointOut(
            id=ep.id,
            hostname=ep.hostname,
            ip_address=ep.ip_address,
            mac_address=ep.mac_address,
            operating_system=ep.operating_system,
            os_version=ep.os_version,
            agent_version=ep.agent_version,
            status=ep.status,
            risk_level=ep.risk_level,
            owner_id=ep.owner_id,
            owner_username=ep.owner.username if ep.owner else "system",
            is_isolated=ep.is_isolated,
            isolation_reason=ep.isolation_reason,
            last_seen=ep.last_seen,
            registered_at=ep.registered_at,
            tags=ep.tags or [],
            event_count=counts["events"],
            detection_count=counts["detections"],
            alert_count=counts["alerts"],
        )

    def delete_endpoint(self, endpoint_id: uuid.UUID, current_user: User) -> None:
        ep = self.repo.get_with_owner(endpoint_id)
        if not ep:
            raise NotFoundError(f"Endpoint with ID '{endpoint_id}' not found.")

        if not self._has_global_access(current_user) and ep.owner_id != current_user.id:
            raise PermissionDeniedError("Access denied: You cannot remove another user's endpoint.")

        hostname = ep.hostname
        self.repo.delete(endpoint_id)

        if self.audit:
            self.audit.log(
                action="ENDPOINT_REMOVED",
                user=current_user,
                object_type="ENDPOINT",
                object_id=str(endpoint_id),
                details={"hostname": hostname},
            )

    def _compute_counts(self, ep: Endpoint) -> dict:
        host_cond = or_(ParsedLog.hostname == ep.hostname, ParsedLog.source_ip == ep.ip_address)
        
        events = self.db.execute(
            select(func.count(ParsedLog.id)).where(host_cond)
        ).scalar_one()

        detections = self.db.execute(
            select(func.count(SigmaDetection.id))
            .join(ParsedLog, SigmaDetection.parsed_log_id == ParsedLog.id)
            .where(host_cond)
        ).scalar_one()

        alerts = self.db.execute(
            select(func.count(Alert.id))
            .join(RiskAssessment, Alert.risk_assessment_id == RiskAssessment.id)
            .join(SigmaDetection, RiskAssessment.sigma_detection_id == SigmaDetection.id)
            .join(ParsedLog, SigmaDetection.parsed_log_id == ParsedLog.id)
            .where(host_cond)
        ).scalar_one()

        critical_alerts = self.db.execute(
            select(func.count(Alert.id))
            .join(RiskAssessment, Alert.risk_assessment_id == RiskAssessment.id)
            .join(SigmaDetection, RiskAssessment.sigma_detection_id == SigmaDetection.id)
            .join(ParsedLog, SigmaDetection.parsed_log_id == ParsedLog.id)
            .where(host_cond, Alert.severity == RiskLevel.CRITICAL)
        ).scalar_one()

        high_alerts = self.db.execute(
            select(func.count(Alert.id))
            .join(RiskAssessment, Alert.risk_assessment_id == RiskAssessment.id)
            .join(SigmaDetection, RiskAssessment.sigma_detection_id == SigmaDetection.id)
            .join(ParsedLog, SigmaDetection.parsed_log_id == ParsedLog.id)
            .where(host_cond, Alert.severity == RiskLevel.HIGH)
        ).scalar_one()

        return {
            "events": events or 0,
            "detections": detections or 0,
            "alerts": alerts or 0,
            "critical_alerts": critical_alerts or 0,
            "high_alerts": high_alerts or 0,
        }

    def _compute_risk_level(self, critical_alerts: int, high_alerts: int, detections: int) -> RiskLevel:
        if critical_alerts > 0:
            return RiskLevel.CRITICAL
        if high_alerts > 0 or detections >= 5:
            return RiskLevel.HIGH
        if detections > 0:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
