"""
RiskAssessment repository — persistence and querying of calculated risk scores.
"""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.enums import RiskLevel
from app.models.risk_assessment import RiskAssessment
from app.repositories.base import BaseRepository


class RiskRepository(BaseRepository[RiskAssessment]):
    def __init__(self, session: Session):
        super().__init__(RiskAssessment, session)

    def get_by_detection_id(self, sigma_detection_id: uuid.UUID) -> RiskAssessment | None:
        stmt = (
            select(RiskAssessment)
            .where(RiskAssessment.sigma_detection_id == sigma_detection_id)
            .order_by(RiskAssessment.calculated_at.desc())
        )
        return self.session.execute(stmt).scalars().first()

    def list_assessments(
        self,
        risk_level: RiskLevel | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[RiskAssessment], int]:
        stmt = select(RiskAssessment)
        count_stmt = select(func.count(RiskAssessment.id))

        if risk_level is not None:
            stmt = stmt.where(RiskAssessment.risk_level == risk_level)
            count_stmt = count_stmt.where(RiskAssessment.risk_level == risk_level)

        total = self.session.execute(count_stmt).scalar_one()
        stmt = stmt.order_by(RiskAssessment.calculated_at.desc()).offset(skip).limit(limit)
        items = self.session.execute(stmt).scalars().all()
        return items, total

    def get_statistics(self) -> dict:
        total = self.session.execute(select(func.count(RiskAssessment.id))).scalar_one()
        avg_score = (
            self.session.execute(select(func.avg(RiskAssessment.risk_score))).scalar_one() or 0.0
        )

        by_level: dict[str, int] = {level.value: 0 for level in RiskLevel}
        level_counts = self.session.execute(
            select(RiskAssessment.risk_level, func.count(RiskAssessment.id)).group_by(
                RiskAssessment.risk_level
            )
        ).all()
        for lvl, cnt in level_counts:
            lvl_val = lvl.value if hasattr(lvl, "value") else str(lvl)
            by_level[lvl_val] = cnt

        return {
            "total_assessments": total,
            "average_risk_score": round(float(avg_score), 1),
            "by_level": by_level,
        }
