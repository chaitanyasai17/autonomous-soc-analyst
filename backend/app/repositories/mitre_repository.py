"""
MitreTechnique repository — queries, reference data lookups, and detection mappings.
"""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.mitre.dataset import TACTICS_CATALOG, TECHNIQUES_CATALOG
from app.models.associations import sigma_detection_mitre_technique
from app.models.mitre_technique import MitreTechnique
from app.repositories.base import BaseRepository


class MitreRepository(BaseRepository[MitreTechnique]):
    def __init__(self, session: Session):
        super().__init__(MitreTechnique, session)

    def get_by_technique_id(self, technique_id: str) -> MitreTechnique | None:
        stmt = select(MitreTechnique).where(
            func.lower(MitreTechnique.technique_id) == technique_id.lower().strip()
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def list_techniques(
        self,
        tactic: str | None = None,
        search: str | None = None,
        skip: int = 0,
        limit: int = 100,
    ) -> tuple[Sequence[MitreTechnique], int]:
        stmt = select(MitreTechnique)
        count_stmt = select(func.count(MitreTechnique.id))

        if tactic:
            stmt = stmt.where(func.lower(MitreTechnique.tactic) == tactic.lower().strip())
            count_stmt = count_stmt.where(func.lower(MitreTechnique.tactic) == tactic.lower().strip())

        if search:
            search_pattern = f"%{search.strip().lower()}%"
            filter_clause = (
                func.lower(MitreTechnique.technique_id).like(search_pattern)
                | func.lower(MitreTechnique.technique_name).like(search_pattern)
                | func.lower(MitreTechnique.tactic).like(search_pattern)
            )
            stmt = stmt.where(filter_clause)
            count_stmt = count_stmt.where(filter_clause)

        total = self.session.execute(count_stmt).scalar_one()
        stmt = stmt.order_by(MitreTechnique.technique_id.asc()).offset(skip).limit(limit)
        items = self.session.execute(stmt).scalars().all()
        return items, total

    def seed_techniques(self) -> int:
        """Seed reference dataset into database if not already present."""
        seeded = 0
        for item in TECHNIQUES_CATALOG:
            existing = self.get_by_technique_id(item["technique_id"])
            if not existing:
                technique = MitreTechnique(
                    id=uuid.uuid4(),
                    technique_id=item["technique_id"],
                    technique_name=item["technique_name"],
                    tactic=item["tactic"],
                    description=item.get("description"),
                    reference_url=item.get("reference_url"),
                )
                self.session.add(technique)
                seeded += 1
        if seeded > 0:
            self.session.commit()
        return seeded

    def link_detection_to_technique(
        self, sigma_detection_id: uuid.UUID, mitre_technique_id: uuid.UUID
    ) -> None:
        """Create join record in association table if it does not exist."""
        stmt = select(sigma_detection_mitre_technique).where(
            sigma_detection_mitre_technique.c.sigma_detection_id == sigma_detection_id,
            sigma_detection_mitre_technique.c.mitre_technique_id == mitre_technique_id,
        )
        exists = self.session.execute(stmt).first()
        if not exists:
            insert_stmt = sigma_detection_mitre_technique.insert().values(
                sigma_detection_id=sigma_detection_id,
                mitre_technique_id=mitre_technique_id,
            )
            self.session.execute(insert_stmt)
            self.session.commit()

    def get_techniques_for_detection(
        self, sigma_detection_id: uuid.UUID
    ) -> Sequence[MitreTechnique]:
        stmt = (
            select(MitreTechnique)
            .join(
                sigma_detection_mitre_technique,
                MitreTechnique.id == sigma_detection_mitre_technique.c.mitre_technique_id,
            )
            .where(sigma_detection_mitre_technique.c.sigma_detection_id == sigma_detection_id)
        )
        return self.session.execute(stmt).scalars().all()

    def get_tactics(self) -> list[dict[str, str]]:
        return TACTICS_CATALOG
