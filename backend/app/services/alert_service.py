"""
Alert service — handles alert creation, triage state transitions, and auto-generation from risk assessments.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Sequence

from sqlalchemy import select

from app.core.exceptions import NotFoundError, ValidationFailedError
from app.models.alert import Alert
from app.models.enums import AlertStatus, RiskLevel
from app.models.risk_assessment import RiskAssessment
from app.models.sigma_detection import SigmaDetection
from app.models.user import User
from app.repositories.alert_repository import AlertRepository
from app.repositories.risk_repository import RiskRepository
from app.repositories.sigma_detection_repository import SigmaDetectionRepository
from app.repositories.user_repository import UserRepository
from app.schemas.alert import (
    AlertCreate,
    AlertOut,
    AlertStatisticsOut,
    AutoGenerateAlertsResponse,
)
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)


class AlertService:
    def __init__(
        self,
        alert_repository: AlertRepository,
        risk_repository: RiskRepository,
        sigma_detection_repository: SigmaDetectionRepository,
        user_repository: UserRepository,
        notification_service: Any | None = None,
    ):
        self.alert_repository = alert_repository
        self.risk_repository = risk_repository
        self.sigma_detection_repository = sigma_detection_repository
        self.user_repository = user_repository
        self.notification_service = notification_service

    def create_alert(self, data: AlertCreate) -> AlertOut:
        alert = Alert(
            id=uuid.uuid4(),
            title=data.title,
            description=data.description,
            severity=data.severity,
            status=AlertStatus.OPEN,
            risk_assessment_id=data.risk_assessment_id,
            incident_id=data.incident_id,
            assigned_to_id=data.assigned_to_id,
            created_at=utc_now(),
        )
        self.alert_repository.create(alert)
        return self._to_out(alert)

    def update_status(self, alert_id: uuid.UUID, new_status: AlertStatus) -> AlertOut:
        alert = self.alert_repository.get_by_id(alert_id)
        if not alert:
            raise NotFoundError(f"Alert with ID '{alert_id}' not found.")

        # State transition validation
        valid_transitions = {
            AlertStatus.OPEN: [AlertStatus.IN_PROGRESS, AlertStatus.RESOLVED, AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE],
            AlertStatus.IN_PROGRESS: [AlertStatus.RESOLVED, AlertStatus.CLOSED, AlertStatus.FALSE_POSITIVE, AlertStatus.OPEN],
            AlertStatus.RESOLVED: [AlertStatus.CLOSED, AlertStatus.IN_PROGRESS],
            AlertStatus.CLOSED: [AlertStatus.IN_PROGRESS, AlertStatus.OPEN],
            AlertStatus.FALSE_POSITIVE: [AlertStatus.IN_PROGRESS, AlertStatus.OPEN],
        }

        allowed = valid_transitions.get(alert.status, [])
        if new_status != alert.status and new_status not in allowed:
            raise ValidationFailedError(
                f"Cannot transition alert from '{alert.status.value}' to '{new_status.value}'."
            )

        alert.status = new_status
        if new_status in (AlertStatus.RESOLVED, AlertStatus.CLOSED):
            alert.resolved_at = utc_now()
        else:
            alert.resolved_at = None

        self.alert_repository.session.commit()
        return self._to_out(alert)

    def assign_alert(self, alert_id: uuid.UUID, user_id: uuid.UUID | None) -> AlertOut:
        alert = self.alert_repository.get_by_id(alert_id)
        if not alert:
            raise NotFoundError(f"Alert with ID '{alert_id}' not found.")

        if user_id:
            user = self.user_repository.get_by_id(user_id)
            if not user:
                raise NotFoundError(f"Assignee user with ID '{user_id}' not found.")
            alert.assigned_to_id = user_id
            if self.notification_service:
                try:
                    self.notification_service.create_notification(
                        recipient_id=user_id,
                        title="Alert Assigned to You",
                        message=f"You have been assigned to Alert: {alert.title}",
                        notification_type="incident_assigned",
                    )
                except Exception as e:
                    logger.warning("Could not dispatch assignment notification: %s", e)
        else:
            alert.assigned_to_id = None

        self.alert_repository.session.commit()
        return self._to_out(alert)

    def auto_generate_alerts(self) -> AutoGenerateAlertsResponse:
        """Scan all RiskAssessments without alerts and generate actionable alerts."""
        stmt = (
            select(RiskAssessment)
            .outerjoin(Alert, Alert.risk_assessment_id == RiskAssessment.id)
            .where(Alert.id.is_(None))
        )
        unalerted = self.alert_repository.session.execute(stmt).scalars().all()
        created_count = 0

        for ra in unalerted:
            detection = self.sigma_detection_repository.get_by_id(ra.sigma_detection_id)
            rule_title = detection.rule_title if detection else "Security Anomaly Detected"
            
            details: list[str] = []
            if detection and detection.parsed_log:
                pl = detection.parsed_log
                if pl.hostname:
                    details.append(f"Host: {pl.hostname}")
                if pl.username:
                    details.append(f"User: {pl.username}")
                if pl.source_ip:
                    details.append(f"Source: {pl.source_ip}")
                if pl.destination_ip:
                    dst_str = f"Dest: {pl.destination_ip}"
                    if pl.destination_port:
                        dst_str += f":{pl.destination_port}"
                    details.append(dst_str)
                if pl.event_type and pl.event_type != "unknown":
                    details.append(f"Type: {pl.event_type}")

            entity_info = f" [{', '.join(details)}]" if details else ""
            desc = (
                f"Autonomous SOC detection triggered by Sigma rule '{rule_title}'{entity_info}. "
                f"Calculated Risk Score: {ra.risk_score}/100 ({ra.risk_level.value.upper()})."
            )
            alert = Alert(
                id=uuid.uuid4(),
                title=f"Security Threat: {rule_title}",
                description=desc,
                severity=ra.risk_level,
                status=AlertStatus.OPEN,
                risk_assessment_id=ra.id,
                created_at=utc_now(),
            )
            self.alert_repository.session.add(alert)
            created_count += 1

        if created_count > 0:
            self.alert_repository.session.commit()

        return AutoGenerateAlertsResponse(
            alerts_created=created_count,
            message=f"Successfully generated {created_count} new alert(s) from risk assessments.",
        )

    def list_alerts(
        self,
        status: AlertStatus | None = None,
        severity: RiskLevel | None = None,
        assigned_to_id: uuid.UUID | None = None,
        incident_id: uuid.UUID | None = None,
        search_query: str | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[AlertOut], int]:
        alerts, total = self.alert_repository.search(
            status=status,
            severity=severity,
            assigned_to_id=assigned_to_id,
            incident_id=incident_id,
            search_query=search_query,
            skip=skip,
            limit=limit,
        )
        return [self._to_out(a) for a in alerts], total

    def get_alert_by_id(self, alert_id: uuid.UUID) -> AlertOut:
        alert = self.alert_repository.get_with_relations(alert_id)
        if not alert:
            raise NotFoundError(f"Alert '{alert_id}' not found.")
        return self._to_out(alert)

    def get_statistics(self) -> AlertStatisticsOut:
        stats = self.alert_repository.get_statistics()
        return AlertStatisticsOut(**stats)

    def _to_out(self, alert: Alert) -> AlertOut:
        assigned_username = alert.assigned_to.username if alert.assigned_to else None
        risk_score = None
        if alert.risk_assessment:
            risk_score = alert.risk_assessment.risk_score
        elif hasattr(alert, "web_finding") and alert.web_finding:
            risk_score = alert.web_finding.risk_score

        return AlertOut(
            id=alert.id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity,
            status=alert.status,
            resolved_at=alert.resolved_at,
            risk_assessment_id=alert.risk_assessment_id,
            incident_id=alert.incident_id,
            assigned_to_id=alert.assigned_to_id,
            created_at=alert.created_at,
            risk_score=risk_score,
            assigned_username=assigned_username,
        )
