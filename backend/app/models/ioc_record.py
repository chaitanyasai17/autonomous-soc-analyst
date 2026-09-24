"""IOCRecord model — stores extracted Indicators of Compromise (Part 9)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.incident import Incident


class IOCRecord(BaseModel):
    """An observable indicator of compromise (IP, domain, hash, user, URL, host, command)."""

    __tablename__ = "ioc_records"
    __table_args__ = (
        Index("ix_ioc_records_type_value", "ioc_type", "value", unique=True),
        Index("ix_ioc_records_type", "ioc_type"),
        Index("ix_ioc_records_last_seen", "last_seen"),
    )

    ioc_type: Mapped[str] = mapped_column(String(50), nullable=False)
    value: Mapped[str] = mapped_column(String(1024), nullable=False)
    source: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=1.0, nullable=False)

    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    related_alert_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True
    )
    related_incident_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True
    )

    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    tags: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    alert: Mapped["Alert | None"] = relationship(foreign_keys=[related_alert_id])
    incident: Mapped["Incident | None"] = relationship(foreign_keys=[related_incident_id])

    def __repr__(self) -> str:
        return f"<IOCRecord id={self.id} type={self.ioc_type} value={self.value!r}>"
