"""
Report repository — database operations for generated report records.
"""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.enums import ReportType
from app.models.report import Report
from app.repositories.base import BaseRepository


class ReportRepository(BaseRepository[Report]):
    def __init__(self, session: Session):
        super().__init__(Report, session)

    def list_reports(
        self,
        report_type: ReportType | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[Report], int]:
        stmt = select(Report).where(Report.deleted_at.is_(None))
        count_stmt = select(func.count(Report.id)).where(Report.deleted_at.is_(None))

        if report_type is not None:
            stmt = stmt.where(Report.report_type == report_type)
            count_stmt = count_stmt.where(Report.report_type == report_type)

        total = self.session.execute(count_stmt).scalar_one()
        stmt = stmt.order_by(Report.generated_at.desc()).offset(skip).limit(limit)
        items = self.session.execute(stmt).scalars().all()
        return items, total
