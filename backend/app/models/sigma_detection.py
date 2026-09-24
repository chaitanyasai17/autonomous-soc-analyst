"""
SigmaDetection model — records a Sigma rule match against a ParsedLog entry.

Part 8 note: matched_fields, rule_category, and rule_tags were added in
Part 8 — Sigma Rule Detection Engine. Part 3's field list was
non-exhaustive and the detection engine explicitly needs to persist which
fields/values triggered a match (variable per rule, hence JSONB rather than
fixed columns) plus the rule's category/tags for filtering and for Part 9's
MITRE mapping (Sigma tags commonly encode attack.txxxx technique ids). A
unique constraint on (parsed_log_id, matched_rule) prevents duplicate
detections when a log is re-scanned against the same rule — purely
additive, no existing column changed.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Index, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.associations import sigma_detection_mitre_technique
from app.models.base import BaseModel
from app.models.enums import RiskLevel
from app.models.sa_types import risk_level_enum

if TYPE_CHECKING:
    from app.models.mitre_technique import MitreTechnique
    from app.models.parsed_log import ParsedLog
    from app.models.risk_assessment import RiskAssessment


class SigmaDetection(BaseModel):
    """A single Sigma rule match produced by the detection engine (Part 8)."""

    __tablename__ = "sigma_detections"
    __table_args__ = (
        Index("ix_sigma_detections_severity", "severity"),
        Index("ix_sigma_detections_detection_timestamp", "detection_timestamp"),
        Index("ix_sigma_detections_rule_category", "rule_category"),
        CheckConstraint(
            "confidence >= 0 AND confidence <= 1", name="ck_sigma_detections_confidence_range"
        ),
        UniqueConstraint(
            "parsed_log_id", "matched_rule", name="uq_sigma_detections_parsed_log_rule"
        ),
    )

    parsed_log_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("parsed_logs.id", ondelete="CASCADE"), nullable=False
    )

    matched_rule: Mapped[str] = mapped_column(String(255), nullable=False)
    rule_title: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[RiskLevel] = mapped_column(
        risk_level_enum,
        nullable=False,
    )
    # 0.0–1.0 confidence score produced by the detection engine (Part 8).
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    detection_timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    # --- Part 8 additions ---
    # List of {"field": ..., "value": ..., "selection": ...} dicts describing
    # exactly what matched. JSONB (not fixed columns) because the set of
    # matched fields varies per rule.
    matched_fields: Mapped[list | None] = mapped_column(JSONB, nullable=True)
    rule_category: Mapped[str | None] = mapped_column(String(50), nullable=True)
    rule_tags: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    # Analyst feedback (Part 17)
    analyst_verdict: Mapped[str | None] = mapped_column(String(50), nullable=True)
    analyst_note: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- Relationships ---
    parsed_log: Mapped["ParsedLog"] = relationship(back_populates="sigma_detections")
    mitre_techniques: Mapped[list["MitreTechnique"]] = relationship(
        secondary=sigma_detection_mitre_technique, back_populates="detections"
    )
    risk_assessments: Mapped[list["RiskAssessment"]] = relationship(
        back_populates="sigma_detection", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<SigmaDetection id={self.id} rule={self.matched_rule!r} severity={self.severity.value}>"
