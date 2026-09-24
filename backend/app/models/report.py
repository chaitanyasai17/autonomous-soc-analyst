"""Report model — a generated PDF/CSV report artifact."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, ForeignKey, Index, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, SoftDeleteMixin
from app.models.enums import ReportType
from app.models.sa_types import report_type_enum

if TYPE_CHECKING:
    from app.models.user import User


class Report(BaseModel, SoftDeleteMixin):
    """A generated report artifact (PDF/CSV), produced by the Reports module (Part 14)."""

    __tablename__ = "reports"
    __table_args__ = (
        Index("ix_reports_report_type", "report_type"),
        Index("ix_reports_generated_at", "generated_at"),
    )

    report_name: Mapped[str] = mapped_column(String(255), nullable=False)
    report_type: Mapped[ReportType] = mapped_column(report_type_enum, nullable=False)
    generated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)

    # Nullable: system-generated reports may not have a human generator.
    generated_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # --- Relationships ---
    generated_by: Mapped["User | None"] = relationship(
        back_populates="generated_reports", foreign_keys=[generated_by_id]
    )

    def __repr__(self) -> str:
        return f"<Report id={self.id} name={self.report_name!r} type={self.report_type.value}>"
