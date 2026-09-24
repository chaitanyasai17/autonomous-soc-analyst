"""Incident model — groups related Alerts under a single investigation."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, SoftDeleteMixin
from app.models.enums import IncidentStatus, RiskLevel
from app.models.sa_types import incident_status_enum, risk_level_enum

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.user import User


class Incident(BaseModel, SoftDeleteMixin):
    """A SOC incident — an investigation grouping one or more related Alerts."""

    __tablename__ = "incidents"
    __table_args__ = (
        Index("ix_incidents_incident_number", "incident_number", unique=True),
        Index("ix_incidents_status", "status"),
        Index("ix_incidents_priority", "priority"),
        Index("ix_incidents_opened_at", "opened_at"),
    )

    incident_number: Mapped[str] = mapped_column(String(50), nullable=False)
    # Reuses RiskLevel — see app/models/enums.py design note.
    priority: Mapped[RiskLevel] = mapped_column(risk_level_enum, nullable=False)
    status: Mapped[IncidentStatus] = mapped_column(
        incident_status_enum, nullable=False, default=IncidentStatus.OPEN
    )
    opened_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Nullable: an incident may not yet have an assigned owner.
    owner_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # --- Relationships ---
    owner: Mapped["User | None"] = relationship(
        back_populates="owned_incidents", foreign_keys=[owner_id]
    )
    alerts: Mapped[list["Alert"]] = relationship(back_populates="incident")

    def __repr__(self) -> str:
        return f"<Incident id={self.id} number={self.incident_number!r} status={self.status.value}>"
