"""
ParsedLog model — a single normalized event parsed out of a SecurityLog file.

Part 6 note: source_port, destination_port, protocol, action, message, and
event_id were added in Part 6 — Log Parser Engine. Part 3's field list was
non-exhaustive ("Fields such as...") and the parser's normalization schema
explicitly requires these. Purely additive — no existing column changed.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.models.enums import RiskLevel
from app.models.sa_types import risk_level_enum

if TYPE_CHECKING:
    from app.models.security_log import SecurityLog
    from app.models.sigma_detection import SigmaDetection


class ParsedLog(BaseModel):
    """A single normalized event parsed out of a raw SecurityLog file."""

    __tablename__ = "parsed_logs"
    __table_args__ = (
        Index("ix_parsed_logs_timestamp", "timestamp"),
        Index("ix_parsed_logs_source_ip", "source_ip"),
        Index("ix_parsed_logs_destination_ip", "destination_ip"),
        Index("ix_parsed_logs_hostname", "hostname"),
        Index("ix_parsed_logs_severity", "severity"),
        Index("ix_parsed_logs_action", "action"),
    )

    security_log_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("security_logs.id", ondelete="CASCADE"),
        nullable=False,
    )

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    destination_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    username: Mapped[str | None] = mapped_column(String(100), nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    severity: Mapped[RiskLevel] = mapped_column(
        risk_level_enum,
        nullable=False,
        default=RiskLevel.LOW,
    )
    raw_log: Mapped[str] = mapped_column(Text, nullable=False)

    # --- Part 6 additions ---
    source_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    destination_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str | None] = mapped_column(String(20), nullable=True)
    action: Mapped[str | None] = mapped_column(String(50), nullable=True)
    message: Mapped[str | None] = mapped_column(Text, nullable=True)
    event_id: Mapped[str | None] = mapped_column(String(100), nullable=True)

    # --- Relationships ---
    security_log: Mapped["SecurityLog"] = relationship(back_populates="parsed_logs")
    sigma_detections: Mapped[list["SigmaDetection"]] = relationship(
        back_populates="parsed_log", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<ParsedLog id={self.id} event_type={self.event_type!r} severity={self.severity.value}>"
