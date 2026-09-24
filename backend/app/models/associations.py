"""
Association tables (many-to-many join tables).

Defined separately from the models they connect so both sides of a
relationship can reference the same Table object without circular imports.
"""

import uuid

from sqlalchemy import Column, ForeignKey, Table
from sqlalchemy.dialects.postgresql import UUID

from app.database.base import Base

# A Sigma detection can map to multiple MITRE techniques, and a technique
# can be referenced by many detections — classic many-to-many. MITRE
# technique reference data (id, name, tactic, description) is NOT duplicated
# per detection; only the relationship is stored here.
sigma_detection_mitre_technique = Table(
    "sigma_detection_mitre_technique",
    Base.metadata,
    Column(
        "sigma_detection_id",
        UUID(as_uuid=True),
        ForeignKey("sigma_detections.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "mitre_technique_id",
        UUID(as_uuid=True),
        ForeignKey("mitre_techniques.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)
