"""
MitreTechnique model — MITRE ATT&CK reference data.

Design note: this is reference/lookup data (one row per ATT&CK technique,
seeded once and rarely changed), not data owned by an individual detection.
A detection can map to multiple techniques and a technique is referenced by
many detections, so the relationship is many-to-many via the
`sigma_detection_mitre_technique` association table — this avoids storing
technique_name/tactic/description/reference_url redundantly on every
detection row.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.associations import sigma_detection_mitre_technique
from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.sigma_detection import SigmaDetection


class MitreTechnique(BaseModel):
    """A single MITRE ATT&CK technique (reference data)."""

    __tablename__ = "mitre_techniques"
    __table_args__ = (
        Index("ix_mitre_techniques_technique_id", "technique_id", unique=True),
        Index("ix_mitre_techniques_tactic", "tactic"),
    )

    technique_id: Mapped[str] = mapped_column(String(20), nullable=False)
    technique_name: Mapped[str] = mapped_column(String(255), nullable=False)
    tactic: Mapped[str] = mapped_column(String(100), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    reference_url: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # --- Relationships ---
    detections: Mapped[list["SigmaDetection"]] = relationship(
        secondary=sigma_detection_mitre_technique, back_populates="mitre_techniques"
    )

    def __repr__(self) -> str:
        return f"<MitreTechnique id={self.id} technique_id={self.technique_id!r}>"
