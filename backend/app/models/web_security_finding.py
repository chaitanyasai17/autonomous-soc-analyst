"""WebSecurityFinding model — a defensive security finding discovered during an authorized scan."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.models.enums import RiskLevel
from app.models.sa_types import risk_level_enum

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.incident import Incident
    from app.models.web_security_scan import WebSecurityScan


class WebSecurityFinding(BaseModel):
    """A defensive web security finding discovered during an authorized audit."""

    __tablename__ = "web_security_findings"
    __table_args__ = (
        Index("ix_web_security_findings_scan_id", "scan_id"),
        Index("ix_web_security_findings_finding_id", "finding_id", unique=True),
        Index("ix_web_security_findings_severity", "severity"),
        Index("ix_web_security_findings_category", "category"),
        Index("ix_web_security_findings_status", "status"),
        Index("ix_web_security_findings_endpoint", "endpoint"),
    )

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("web_security_scans.id", ondelete="CASCADE"), nullable=False
    )
    finding_id: Mapped[str] = mapped_column(String(50), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[RiskLevel] = mapped_column(risk_level_enum, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="CONFIRMED", nullable=False)

    endpoint: Mapped[str] = mapped_column(String(1024), nullable=False)
    http_method: Mapped[str] = mapped_column(String(10), default="GET", nullable=False)
    parameter: Mapped[str | None] = mapped_column(String(255), nullable=True)

    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)

    cwe_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    owasp_category: Mapped[str | None] = mapped_column(String(100), nullable=True)
    mitre_technique_id: Mapped[str | None] = mapped_column(String(50), nullable=True)
    affected_component: Mapped[str | None] = mapped_column(String(255), nullable=True)

    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)

    related_alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    related_incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )
    analyst_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    scan: Mapped["WebSecurityScan"] = relationship(back_populates="findings")
    alert: Mapped["Alert | None"] = relationship(foreign_keys=[related_alert_id])
    incident: Mapped["Incident | None"] = relationship(foreign_keys=[related_incident_id])

    def __repr__(self) -> str:
        return f"<WebSecurityFinding id={self.id} finding_id={self.finding_id!r} title={self.title!r} sev={self.severity.value}>"
