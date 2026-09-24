"""Alert model — an actionable alert, optionally traced back to the RiskAssessment that triggered it."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, SoftDeleteMixin
from app.models.enums import AlertStatus, RiskLevel
from app.models.sa_types import alert_status_enum, risk_level_enum

if TYPE_CHECKING:
    from app.models.incident import Incident
    from app.models.risk_assessment import RiskAssessment
    from app.models.user import User
    from app.models.web_security_finding import WebSecurityFinding


class Alert(BaseModel, SoftDeleteMixin):
    """A SOC alert — may be grouped into an Incident and assigned to a User."""

    __tablename__ = "alerts"
    __table_args__ = (
        Index("ix_alerts_severity", "severity"),
        Index("ix_alerts_status", "status"),
        Index("ix_alerts_created_at", "created_at"),
    )

    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[RiskLevel] = mapped_column(risk_level_enum, nullable=False)
    status: Mapped[AlertStatus] = mapped_column(
        alert_status_enum, nullable=False, default=AlertStatus.OPEN
    )
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Nullable: an alert can exist without ever having been auto-triggered by
    # a risk assessment (e.g., manually created by an analyst).
    risk_assessment_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("risk_assessments.id", ondelete="SET NULL"), nullable=True
    )
    # Nullable: an alert may not yet be grouped into an incident.
    incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
    # Nullable: an alert may be unassigned.
    assigned_to_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    # Nullable: an alert promoted from a Web Security Finding
    web_finding_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("web_security_findings.id", ondelete="SET NULL"), nullable=True
    )

    # --- Relationships ---
    risk_assessment: Mapped["RiskAssessment | None"] = relationship(back_populates="alerts")
    incident: Mapped["Incident | None"] = relationship(back_populates="alerts")
    assigned_to: Mapped["User | None"] = relationship(
        back_populates="assigned_alerts", foreign_keys=[assigned_to_id]
    )
    web_finding: Mapped["WebSecurityFinding | None"] = relationship(foreign_keys=[web_finding_id])

    @property
    def risk_score(self) -> float | None:
        if self.risk_assessment:
            return self.risk_assessment.risk_score
        if self.web_finding:
            return self.web_finding.risk_score
        return None

    def __repr__(self) -> str:
        return f"<Alert id={self.id} title={self.title!r} status={self.status.value}>"
