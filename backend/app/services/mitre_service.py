"""
MITRE ATT&CK service — business logic for technique lookups, Sigma tag mapping, and matrix generation.
"""

from __future__ import annotations

import logging
import uuid
from typing import Sequence

from sqlalchemy import func, select

from app.core.exceptions import NotFoundError
from app.models.associations import sigma_detection_mitre_technique
from app.models.mitre_technique import MitreTechnique
from app.models.sigma_detection import SigmaDetection
from app.repositories.mitre_repository import MitreRepository
from app.schemas.mitre import (
    MitreMatrixColumn,
    MitreMatrixOut,
    MitreTacticOut,
    MitreTechniqueOut,
)

logger = logging.getLogger(__name__)


class MitreService:
    def __init__(self, mitre_repository: MitreRepository):
        self.repository = mitre_repository

    def seed_if_empty(self) -> int:
        return self.repository.seed_techniques()

    def get_technique(self, technique_id: str) -> MitreTechnique:
        technique = self.repository.get_by_technique_id(technique_id)
        if not technique:
            # Try by UUID
            try:
                val = uuid.UUID(technique_id)
                technique = self.repository.get_by_id(val)
            except ValueError:
                pass
        if not technique:
            raise NotFoundError(f"MITRE technique '{technique_id}' not found.")
        return technique

    def list_techniques(
        self,
        tactic: str | None = None,
        search: str | None = None,
        skip: int = 0,
        limit: int = 100,
    ) -> tuple[list[MitreTechniqueOut], int]:
        self.seed_if_empty()
        techniques, total = self.repository.list_techniques(
            tactic=tactic, search=search, skip=skip, limit=limit
        )

        # Count active detections for these techniques
        results: list[MitreTechniqueOut] = []
        for t in techniques:
            det_count = self._get_detection_count_for_technique(t.id)
            results.append(
                MitreTechniqueOut(
                    id=t.id,
                    technique_id=t.technique_id,
                    technique_name=t.technique_name,
                    tactic=t.tactic,
                    description=t.description,
                    reference_url=t.reference_url,
                    detection_count=det_count,
                )
            )
        return results, total

    def _get_detection_count_for_technique(self, mitre_id: uuid.UUID) -> int:
        stmt = select(func.count(sigma_detection_mitre_technique.c.sigma_detection_id)).where(
            sigma_detection_mitre_technique.c.mitre_technique_id == mitre_id
        )
        return self.repository.session.execute(stmt).scalar_one() or 0

    def get_tactics(self) -> list[MitreTacticOut]:
        self.seed_if_empty()
        tactics_data = self.repository.get_tactics()
        result: list[MitreTacticOut] = []
        for tac in tactics_data:
            tactic_slug = tac["short_name"]
            techniques, _ = self.repository.list_techniques(tactic=tactic_slug, limit=1000)
            det_count = 0
            for t in techniques:
                det_count += self._get_detection_count_for_technique(t.id)
            result.append(
                MitreTacticOut(
                    id=tac["id"],
                    short_name=tac["short_name"],
                    name=tac["name"],
                    description=tac["description"],
                    techniques_count=len(techniques),
                    active_detections_count=det_count,
                )
            )
        return result

    def get_matrix(self) -> MitreMatrixOut:
        self.seed_if_empty()
        tactics_list = self.get_tactics()
        matrix_columns: list[MitreMatrixColumn] = []
        total_detections_mapped = 0
        total_techniques = 0

        for tactic_out in tactics_list:
            techs, _ = self.list_techniques(tactic=tactic_out.short_name, limit=100)
            total_techniques += len(techs)
            matrix_columns.append(MitreMatrixColumn(tactic=tactic_out, techniques=techs))

        distinct_stmt = select(
            func.count(func.distinct(sigma_detection_mitre_technique.c.sigma_detection_id))
        )
        total_detections_mapped = self.repository.session.execute(distinct_stmt).scalar_one() or 0

        return MitreMatrixOut(
            tactics=matrix_columns,
            total_tactics=len(matrix_columns),
            total_techniques=total_techniques,
            total_detections_mapped=total_detections_mapped,
        )

    def map_and_link_detection_tags(
        self, detection: SigmaDetection, tags: list[str]
    ) -> list[MitreTechnique]:
        """Extract MITRE technique IDs from Sigma tags and link to detection in DB."""
        self.seed_if_empty()
        linked: list[MitreTechnique] = []
        if not tags:
            return linked

        for raw_tag in tags:
            tag = raw_tag.lower().strip()
            # Sigma rules use format: attack.t1218 or attack.t1059.001
            if tag.startswith("attack.t"):
                tech_id = tag.replace("attack.", "").upper()
                technique = self.repository.get_by_technique_id(tech_id)
                if technique:
                    self.repository.link_detection_to_technique(detection.id, technique.id)
                    linked.append(technique)
            elif tag.startswith("attack."):
                # E.g. attack.execution, attack.defense_evasion
                tactic_name = tag.replace("attack.", "")
                matching_techs, _ = self.repository.list_techniques(tactic=tactic_name, limit=5)
                for mt in matching_techs:
                    self.repository.link_detection_to_technique(detection.id, mt.id)
                    linked.append(mt)
        return linked
