"""
Incident Service — manages SOC incident investigations, lifecycle validation, and automated correlation.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Sequence

from sqlalchemy import select

from app.core.exceptions import NotFoundError, ValidationFailedError
from app.models.alert import Alert
from app.models.enums import AlertStatus, IncidentStatus, RiskLevel
from app.models.incident import Incident
from app.repositories.alert_repository import AlertRepository
from app.repositories.incident_repository import IncidentRepository
from app.repositories.user_repository import UserRepository
from app.schemas.alert import AlertOut
from app.schemas.incident import (
    AutoCorrelateResponse,
    IncidentCreate,
    IncidentOut,
    IncidentStatisticsOut,
    IncidentTimelineEventOut,
    IncidentTimelineOut,
)
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)

# Valid state transitions for Incident lifecycle
INCIDENT_TRANSITIONS: dict[IncidentStatus, list[IncidentStatus]] = {
    IncidentStatus.OPEN: [IncidentStatus.INVESTIGATING, IncidentStatus.CONTAINED, IncidentStatus.CLOSED],
    IncidentStatus.INVESTIGATING: [IncidentStatus.CONTAINED, IncidentStatus.RESOLVED, IncidentStatus.OPEN, IncidentStatus.CLOSED],
    IncidentStatus.CONTAINED: [IncidentStatus.RESOLVED, IncidentStatus.INVESTIGATING, IncidentStatus.CLOSED],
    IncidentStatus.RESOLVED: [IncidentStatus.CLOSED, IncidentStatus.INVESTIGATING],
    IncidentStatus.CLOSED: [IncidentStatus.INVESTIGATING, IncidentStatus.OPEN],
}


class IncidentService:
    def __init__(
        self,
        incident_repository: IncidentRepository,
        alert_repository: AlertRepository,
        user_repository: UserRepository,
        notification_service: Any | None = None,
    ):
        self.incident_repository = incident_repository
        self.alert_repository = alert_repository
        self.user_repository = user_repository
        self.notification_service = notification_service

    def create_incident(self, data: IncidentCreate) -> IncidentOut:
        inc_number = self.incident_repository.next_incident_number()
        incident = Incident(
            id=uuid.uuid4(),
            incident_number=inc_number,
            priority=data.priority,
            status=IncidentStatus.OPEN,
            opened_at=utc_now(),
            owner_id=data.owner_id,
        )
        self.incident_repository.create(incident)

        # Associate alerts if provided
        if data.alert_ids:
            for aid in data.alert_ids:
                alert = self.alert_repository.get_by_id(aid)
                if alert:
                    alert.incident_id = incident.id
            self.alert_repository.session.commit()

        return self.get_incident_or_404(incident.id)

    def update_status(self, incident_id: uuid.UUID, new_status: IncidentStatus) -> IncidentOut:
        incident = self.incident_repository.get_by_id(incident_id)
        if not incident:
            raise NotFoundError(f"Incident '{incident_id}' not found.")

        allowed = INCIDENT_TRANSITIONS.get(incident.status, [])
        if new_status != incident.status and new_status not in allowed:
            raise ValidationFailedError(
                f"Invalid lifecycle transition from '{incident.status.value}' to '{new_status.value}'."
            )

        incident.status = new_status
        if new_status in (IncidentStatus.RESOLVED, IncidentStatus.CLOSED):
            incident.closed_at = utc_now()
        else:
            incident.closed_at = None

        self.incident_repository.session.commit()
        return self.get_incident_or_404(incident.id)

    def assign_owner(self, incident_id: uuid.UUID, user_id: uuid.UUID | None) -> IncidentOut:
        incident = self.incident_repository.get_by_id(incident_id)
        if not incident:
            raise NotFoundError(f"Incident '{incident_id}' not found.")

        if user_id:
            user = self.user_repository.get_by_id(user_id)
            if not user:
                raise NotFoundError(f"User '{user_id}' not found.")
            incident.owner_id = user_id
            if self.notification_service:
                try:
                    self.notification_service.create_notification(
                        recipient_id=user_id,
                        title=f"Incident {incident.incident_number} Assigned",
                        message=f"You have been assigned as lead investigator for incident {incident.incident_number}.",
                        notification_type="incident_assigned",
                    )
                except Exception as e:
                    logger.warning("Could not dispatch incident notification: %s", e)
        else:
            incident.owner_id = None

        self.incident_repository.session.commit()
        return self.get_incident_or_404(incident.id)

    def link_alerts(self, incident_id: uuid.UUID, alert_ids: list[uuid.UUID]) -> IncidentOut:
        incident = self.incident_repository.get_by_id(incident_id)
        if not incident:
            raise NotFoundError(f"Incident '{incident_id}' not found.")

        for aid in alert_ids:
            alert = self.alert_repository.get_by_id(aid)
            if alert:
                alert.incident_id = incident.id
        self.alert_repository.session.commit()
        return self.get_incident_or_404(incident.id)

    def auto_correlate(self) -> AutoCorrelateResponse:
        """
        Automated Correlation Engine:
        Finds unassigned alerts and groups them into incidents based on severity and shared patterns.
        """
        stmt = select(Alert).where(Alert.incident_id.is_(None), Alert.deleted_at.is_(None))
        unlinked = self.alert_repository.session.execute(stmt).scalars().all()

        if not unlinked:
            return AutoCorrelateResponse(
                incidents_created=0,
                alerts_grouped=0,
                message="No unlinked alerts available for correlation.",
            )

        # Group critical/high alerts into one incident, and medium/low into another
        critical_high = [a for a in unlinked if a.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH)]
        medium_low = [a for a in unlinked if a.severity in (RiskLevel.MEDIUM, RiskLevel.LOW)]

        created_count = 0
        grouped_alerts = 0

        if critical_high:
            inc_num = self.incident_repository.next_incident_number()
            inc = Incident(
                id=uuid.uuid4(),
                incident_number=inc_num,
                priority=RiskLevel.CRITICAL,
                status=IncidentStatus.OPEN,
                opened_at=utc_now(),
            )
            self.incident_repository.session.add(inc)
            for a in critical_high:
                a.incident_id = inc.id
                grouped_alerts += 1
            created_count += 1

        if medium_low:
            inc_num = self.incident_repository.next_incident_number()
            inc = Incident(
                id=uuid.uuid4(),
                incident_number=inc_num,
                priority=RiskLevel.MEDIUM,
                status=IncidentStatus.OPEN,
                opened_at=utc_now(),
            )
            self.incident_repository.session.add(inc)
            for a in medium_low:
                a.incident_id = inc.id
                grouped_alerts += 1
            created_count += 1

        self.incident_repository.session.commit()

        return AutoCorrelateResponse(
            incidents_created=created_count,
            alerts_grouped=grouped_alerts,
            message=f"Correlation engine created {created_count} incident(s) consolidating {grouped_alerts} alert(s).",
        )

    def list_incidents(
        self,
        status: IncidentStatus | None = None,
        priority: RiskLevel | None = None,
        owner_id: uuid.UUID | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[IncidentOut], int]:
        incidents, total = self.incident_repository.search(
            status=status, priority=priority, owner_id=owner_id, skip=skip, limit=limit
        )
        return [self._to_out(i) for i in incidents], total

    def get_incident_or_404(self, incident_id: uuid.UUID) -> IncidentOut:
        incident = self.incident_repository.get_with_relations(incident_id)
        if not incident:
            raise NotFoundError(f"Incident '{incident_id}' not found.")
        return self._to_out(incident)

    def get_statistics(self) -> IncidentStatisticsOut:
        stats = self.incident_repository.get_statistics()
        return IncidentStatisticsOut(**stats)

    def get_timeline(self, incident_id: uuid.UUID) -> IncidentTimelineOut:
        """Compile a chronological forensic timeline of all events tied to this incident."""
        incident = self.incident_repository.get_with_relations(incident_id)
        if not incident:
            raise NotFoundError(f"Incident '{incident_id}' not found.")

        timeline_events: list[IncidentTimelineEventOut] = []

        # 1. Incident opened
        timeline_events.append(
            IncidentTimelineEventOut(
                event_id=f"INC-OPEN-{incident.id}",
                timestamp=incident.opened_at,
                event_type="INCIDENT_CREATED",
                title=f"Incident {incident.incident_number} Created",
                description=f"Incident initialized with priority {incident.priority.value.upper()}.",
                severity=incident.priority.value,
                source="INCIDENT_MANAGER",
            )
        )

        # 2. Associated Alerts & Findings
        for alert in (incident.alerts or []):
            timeline_events.append(
                IncidentTimelineEventOut(
                    event_id=f"ALERT-{alert.id}",
                    timestamp=alert.created_at,
                    event_type="ALERT_TRIGGERED",
                    title=f"Alert Triggered: {alert.title}",
                    description=alert.description or "Alert ingested into SOC pipeline.",
                    severity=alert.severity.value,
                    source="ALERT_MANAGER",
                    metadata={"alert_id": str(alert.id), "status": alert.status.value},
                )
            )

            if alert.risk_assessment:
                timeline_events.append(
                    IncidentTimelineEventOut(
                        event_id=f"RISK-{alert.risk_assessment.id}",
                        timestamp=alert.risk_assessment.calculated_at,
                        event_type="RISK_ASSESSED",
                        title=f"Risk Score Assessed: {alert.risk_assessment.risk_score}/100",
                        description=f"Calculated risk level: {alert.risk_assessment.risk_level.value.upper()}.",
                        severity=alert.risk_assessment.risk_level.value,
                        source="RISK_ENGINE",
                        metadata={"risk_score": alert.risk_assessment.risk_score},
                    )
                )

            if alert.web_finding_id:
                timeline_events.append(
                    IncidentTimelineEventOut(
                        event_id=f"WEB-{alert.web_finding_id}",
                        timestamp=alert.created_at,
                        event_type="WEB_FINDING_LINKED",
                        title="Web Security Finding Correlated",
                        description=f"Linked defensive web finding to alert {alert.id}.",
                        severity=alert.severity.value,
                        source="WEB_SECURITY_SCANNER",
                        metadata={"web_finding_id": str(alert.web_finding_id)},
                    )
                )

            if alert.resolved_at:
                timeline_events.append(
                    IncidentTimelineEventOut(
                        event_id=f"ALERT-RES-{alert.id}",
                        timestamp=alert.resolved_at,
                        event_type="ALERT_RESOLVED",
                        title=f"Alert Resolved: {alert.title}",
                        description=f"Alert marked as {alert.status.value}.",
                        severity=alert.severity.value,
                        source="ALERT_MANAGER",
                    )
                )

        # 3. Incident closed
        if incident.closed_at:
            timeline_events.append(
                IncidentTimelineEventOut(
                    event_id=f"INC-CLOSE-{incident.id}",
                    timestamp=incident.closed_at,
                    event_type="INCIDENT_CLOSED",
                    title=f"Incident {incident.incident_number} Closed",
                    description=f"Incident marked as {incident.status.value}.",
                    severity=incident.priority.value,
                    source="INCIDENT_MANAGER",
                )
            )

        # Sort timeline chronologically
        timeline_events.sort(key=lambda e: e.timestamp)

        return IncidentTimelineOut(
            incident_id=incident.id,
            incident_number=incident.incident_number,
            total_events=len(timeline_events),
            events=timeline_events,
        )


    def _to_out(self, incident: Incident) -> IncidentOut:
        owner_name = incident.owner.username if incident.owner else None
        alerts_out = [
            AlertOut(
                id=a.id,
                title=a.title,
                description=a.description,
                severity=a.severity,
                status=a.status,
                resolved_at=a.resolved_at,
                risk_assessment_id=a.risk_assessment_id,
                incident_id=a.incident_id,
                assigned_to_id=a.assigned_to_id,
                created_at=a.created_at,
                risk_score=a.risk_assessment.risk_score if a.risk_assessment else None,
                assigned_username=a.assigned_to.username if a.assigned_to else None,
            )
            for a in (incident.alerts or [])
        ]
        return IncidentOut(
            id=incident.id,
            incident_number=incident.incident_number,
            priority=incident.priority,
            status=incident.status,
            opened_at=incident.opened_at,
            closed_at=incident.closed_at,
            owner_id=incident.owner_id,
            owner_username=owner_name,
            alert_count=len(alerts_out),
            alerts=alerts_out,
        )
