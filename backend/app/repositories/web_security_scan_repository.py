"""WebSecurityScanRepository — database repository for web security audits."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.models.web_security_scan import WebSecurityScan
from app.repositories.base import BaseRepository


class WebSecurityScanRepository(BaseRepository[WebSecurityScan]):
    def __init__(self, session: Session):
        super().__init__(WebSecurityScan, session)

    def get_by_scan_id(self, scan_id: str) -> WebSecurityScan | None:
        stmt = (
            select(WebSecurityScan)
            .options(joinedload(WebSecurityScan.findings))
            .where(WebSecurityScan.scan_id == scan_id.strip())
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def get_with_findings(self, id: uuid.UUID) -> WebSecurityScan | None:
        stmt = (
            select(WebSecurityScan)
            .options(joinedload(WebSecurityScan.findings))
            .where(WebSecurityScan.id == id)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def list_scans(
        self,
        target_host: str | None = None,
        status: str | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[WebSecurityScan], int]:
        stmt = select(WebSecurityScan)
        count_stmt = select(func.count(WebSecurityScan.id))

        if target_host:
            stmt = stmt.where(WebSecurityScan.target_host.ilike(f"%{target_host.strip()}%"))
            count_stmt = count_stmt.where(WebSecurityScan.target_host.ilike(f"%{target_host.strip()}%"))
        if status:
            stmt = stmt.where(WebSecurityScan.status == status)
            count_stmt = count_stmt.where(WebSecurityScan.status == status)

        total = self.session.execute(count_stmt).scalar_one()
        stmt = stmt.order_by(WebSecurityScan.started_at.desc()).offset(skip).limit(limit)
        items = self.session.execute(stmt).scalars().all()
        return items, total

    def get_latest_completed(self, target_host: str | None = None) -> WebSecurityScan | None:
        stmt = (
            select(WebSecurityScan)
            .where(WebSecurityScan.status == "completed")
            .order_by(WebSecurityScan.completed_at.desc())
        )
        if target_host:
            stmt = stmt.where(WebSecurityScan.target_host == target_host.strip())
        return self.session.execute(stmt.limit(1)).scalars().first()

    def get_statistics(self) -> dict:
        total_scans = self.session.execute(select(func.count(WebSecurityScan.id))).scalar_one()
        avg_score = (
            self.session.execute(
                select(func.avg(WebSecurityScan.posture_score)).where(WebSecurityScan.status == "completed")
            ).scalar_one()
            or 100.0
        )
        total_targets = (
            self.session.execute(select(func.count(func.distinct(WebSecurityScan.target_host)))).scalar_one()
            or 0
        )
        return {
            "total_scans": total_scans,
            "average_posture_score": round(float(avg_score), 1),
            "targets_monitored": total_targets,
        }
