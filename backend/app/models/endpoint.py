"""Endpoint model — manages authorized computers connected to the SOC."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, SoftDeleteMixin
from app.models.enums import RiskLevel
from app.models.sa_types import risk_level_enum
from app.utils.datetime_utils import utc_now

if TYPE_CHECKING:
    from app.models.user import User


class Endpoint(BaseModel, SoftDeleteMixin):
    """An enrolled host or workstation monitored by the SOC."""

    __tablename__ = "endpoints"
    __table_args__ = (
        Index("ix_endpoints_hostname", "hostname", unique=True),
        Index("ix_endpoints_ip_address", "ip_address"),
        Index("ix_endpoints_status", "status"),
        Index("ix_endpoints_risk_level", "risk_level"),
        Index("ix_endpoints_owner_id", "owner_id"),
        Index("ix_endpoints_last_seen", "last_seen"),
    )

    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    mac_address: Mapped[str | None] = mapped_column(String(50), nullable=True)
    operating_system: Mapped[str] = mapped_column(String(100), nullable=False, default="Windows 11 Enterprise")
    os_version: Mapped[str | None] = mapped_column(String(50), nullable=True, default="23H2")
    agent_version: Mapped[str] = mapped_column(String(50), nullable=False, default="1.4.2-asoc")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="online")
    risk_level: Mapped[RiskLevel] = mapped_column(risk_level_enum, nullable=False, default=RiskLevel.LOW)

    # Ownership: Enforces that endpoints belong to an authorized user/org
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    owner: Mapped["User"] = relationship(foreign_keys=[owner_id])

    # Containment / Isolation
    is_isolated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    isolation_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)

    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    registered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    tags: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    def __repr__(self) -> str:
        return f"<Endpoint id={self.id} hostname={self.hostname!r} status={self.status} risk={self.risk_level.value}>"
