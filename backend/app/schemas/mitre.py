"""
MITRE ATT&CK Pydantic schemas.
"""

from __future__ import annotations

import uuid
from typing import List, Optional

from app.schemas.base import BaseSchema


class MitreTechniqueOut(BaseSchema):
    id: uuid.UUID
    technique_id: str
    technique_name: str
    tactic: str
    description: Optional[str] = None
    reference_url: Optional[str] = None
    detection_count: int = 0


class MitreTacticOut(BaseSchema):
    id: str
    short_name: str
    name: str
    description: str
    techniques_count: int = 0
    active_detections_count: int = 0


class MitreMatrixColumn(BaseSchema):
    tactic: MitreTacticOut
    techniques: List[MitreTechniqueOut]


class MitreMatrixOut(BaseSchema):
    tactics: List[MitreMatrixColumn]
    total_tactics: int
    total_techniques: int
    total_detections_mapped: int


class MitreSeedResponse(BaseSchema):
    techniques_seeded: int
    message: str
