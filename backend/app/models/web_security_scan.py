"""WebSecurityScan model — records an authorized web application security testing session."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.user import User
    from app.models.web_security_finding import WebSecurityFinding


class WebSecurityScan(BaseModel):
    """An authorized web application security audit session."""

    __tablename__ = "web_security_scans"
    __table_args__ = (
        Index("ix_web_security_scans_scan_id", "scan_id", unique=True),
        Index("ix_web_security_scans_status", "status"),
        Index("ix_web_security_scans_started_at", "started_at"),
        Index("ix_web_security_scans_target_host", "target_host"),
    )

    scan_id: Mapped[str] = mapped_column(String(50), nullable=False)
    target_url: Mapped[str] = mapped_column(String(1024), nullable=False)
    target_host: Mapped[str] = mapped_column(String(255), nullable=False)
    resolved_ip: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scan_profile: Mapped[str] = mapped_column(String(50), nullable=False, default="standard")
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="queued")

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)

    pages_checked: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    endpoints_checked: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    findings_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    informational_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    posture_score: Mapped[float] = mapped_column(Float, default=100.0, nullable=False)
    posture_breakdown: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    exposed_services: Mapped[list | dict | None] = mapped_column(JSONB, nullable=True)

    initiated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    initiated_by_username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Relationships
    initiated_by: Mapped["User | None"] = relationship(foreign_keys=[initiated_by_id])
    findings: Mapped[list["WebSecurityFinding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<WebSecurityScan id={self.id} scan_id={self.scan_id!r} target={self.target_host!r} status={self.status}>"
