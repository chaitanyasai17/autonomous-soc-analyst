"""RiskAssessment model — a calculated risk score for a SigmaDetection, produced by the Risk Scoring Engine (Part 11)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.models.enums import RiskLevel
from app.models.sa_types import risk_level_enum

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.sigma_detection import SigmaDetection


class RiskAssessment(BaseModel):
    """
    A single risk calculation run against a SigmaDetection.

    Modeled as one-to-many from SigmaDetection (not one-to-one) because the
    risk scoring engine may re-evaluate the same detection over time (e.g.,
    after new context becomes available), producing a history of assessments.
    """

    __tablename__ = "risk_assessments"
    __table_args__ = (
        Index("ix_risk_assessments_risk_level", "risk_level"),
        Index("ix_risk_assessments_calculated_at", "calculated_at"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_risk_assessments_score_range"),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name="ck_risk_assessments_confidence_range"
        ),
    )

    sigma_detection_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("sigma_detections.id", ondelete="CASCADE"), nullable=False
    )

    # 0–100 composite risk score produced by the risk engine (Part 11).
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    risk_level: Mapped[RiskLevel] = mapped_column(risk_level_enum, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    calculated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # --- Relationships ---
    sigma_detection: Mapped["SigmaDetection"] = relationship(back_populates="risk_assessments")
    alerts: Mapped[list["Alert"]] = relationship(back_populates="risk_assessment")

    def __repr__(self) -> str:
        return f"<RiskAssessment id={self.id} risk_score={self.risk_score} risk_level={self.risk_level.value}>"
