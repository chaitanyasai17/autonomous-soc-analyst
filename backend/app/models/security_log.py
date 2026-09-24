"""
SecurityLog model — an uploaded raw log file, prior to parsing/normalization.

Part 5 note: file_size, mime_type, storage_path, and checksum_sha256 were
added in Part 5 — Log Upload Module. Part 3's field list was introduced with
"Fields such as..." (non-exhaustive), and the upload module explicitly
requires these for validation, storage bookkeeping, and duplicate-content
detection. This is a purely additive change — no existing column was
renamed, retyped, or removed. `storage_path` is intentionally excluded from
every API response schema (see app/schemas/security_log.py) so filesystem
layout is never exposed to clients.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.models.enums import LogSource, ProcessingStatus
from app.models.sa_types import log_source_enum, processing_status_enum

if TYPE_CHECKING:
    from app.models.parsed_log import ParsedLog
    from app.models.user import User


class SecurityLog(BaseModel):
    """A single uploaded log file awaiting or undergoing parsing."""

    __tablename__ = "security_logs"
    __table_args__ = (
        Index("ix_security_logs_processing_status", "processing_status"),
        Index("ix_security_logs_upload_time", "upload_time"),
        Index("ix_security_logs_checksum_sha256", "checksum_sha256"),
    )

    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    log_source: Mapped[LogSource] = mapped_column(log_source_enum, nullable=False)
    file_type: Mapped[str] = mapped_column(String(20), nullable=False)

    uploaded_by_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    upload_time: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    processing_status: Mapped[ProcessingStatus] = mapped_column(
        processing_status_enum,
        nullable=False,
        default=ProcessingStatus.PENDING,
    )

    # --- Part 5 additions ---
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    # Relative path under settings.UPLOAD_DIRECTORY — never returned by the API.
    storage_path: Mapped[str] = mapped_column(String(500), nullable=False)
    checksum_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    # --- Relationships ---
    uploaded_by: Mapped["User"] = relationship(
        back_populates="uploaded_logs", foreign_keys=[uploaded_by_id]
    )
    parsed_logs: Mapped[list["ParsedLog"]] = relationship(
        back_populates="security_log", cascade="all, delete-orphan"
    )

    @property
    def event_count(self) -> int:
        if hasattr(self, "_event_count"):
            return self._event_count
        if "parsed_logs" in self.__dict__ and self.parsed_logs is not None:
            return len(self.parsed_logs)
        return 0

    @event_count.setter
    def event_count(self, value: int) -> None:
        self._event_count = value

    def __repr__(self) -> str:
        return f"<SecurityLog id={self.id} filename={self.filename!r} status={self.processing_status.value}>"
