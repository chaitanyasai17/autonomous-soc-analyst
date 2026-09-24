"""WebSecurityFindingRepository — database repository for web findings."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.models.enums import RiskLevel
from app.models.web_security_finding import WebSecurityFinding
from app.repositories.base import BaseRepository


class WebSecurityFindingRepository(BaseRepository[WebSecurityFinding]):
    def __init__(self, session: Session):
        super().__init__(WebSecurityFinding, session)

    def get_by_finding_id(self, finding_id: str) -> WebSecurityFinding | None:
        stmt = (
            select(WebSecurityFinding)
            .options(joinedload(WebSecurityFinding.scan), joinedload(WebSecurityFinding.alert))
            .where(WebSecurityFinding.finding_id == finding_id.strip())
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def get_with_relations(self, id: uuid.UUID) -> WebSecurityFinding | None:
        stmt = (
            select(WebSecurityFinding)
            .options(joinedload(WebSecurityFinding.scan), joinedload(WebSecurityFinding.alert))
            .where(WebSecurityFinding.id == id)
        )
        return self.session.execute(stmt).unique().scalar_one_or_none()

    def list_findings(
        self,
        scan_id: uuid.UUID | None = None,
        severity: RiskLevel | None = None,
        category: str | None = None,
        status: str | None = None,
        search: str | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[WebSecurityFinding], int]:
        stmt = select(WebSecurityFinding).options(joinedload(WebSecurityFinding.scan))
        count_stmt = select(func.count(WebSecurityFinding.id))

        if scan_id:
            stmt = stmt.where(WebSecurityFinding.scan_id == scan_id)
            count_stmt = count_stmt.where(WebSecurityFinding.scan_id == scan_id)
        if severity:
            stmt = stmt.where(WebSecurityFinding.severity == severity)
            count_stmt = count_stmt.where(WebSecurityFinding.severity == severity)
        if category:
            stmt = stmt.where(WebSecurityFinding.category == category)
            count_stmt = count_stmt.where(WebSecurityFinding.category == category)
        if status:
            stmt = stmt.where(WebSecurityFinding.status == status)
            count_stmt = count_stmt.where(WebSecurityFinding.status == status)
        if search:
            pattern = f"%{search.strip()}%"
            stmt = stmt.where(
                WebSecurityFinding.title.ilike(pattern)
                | WebSecurityFinding.endpoint.ilike(pattern)
                | WebSecurityFinding.finding_id.ilike(pattern)
            )
            count_stmt = count_stmt.where(
                WebSecurityFinding.title.ilike(pattern)
                | WebSecurityFinding.endpoint.ilike(pattern)
                | WebSecurityFinding.finding_id.ilike(pattern)
            )

        total = self.session.execute(count_stmt).scalar_one()
        stmt = stmt.order_by(WebSecurityFinding.discovered_at.desc()).offset(skip).limit(limit)
        items = self.session.execute(stmt).scalars().all()
        return items, total

    def get_top_vulnerable_endpoints(self, limit: int = 5) -> list[dict]:
        stmt = (
            select(
                WebSecurityFinding.endpoint,
                func.count(WebSecurityFinding.id).label("findings_count"),
                func.max(WebSecurityFinding.severity).label("max_severity"),
            )
            .where(WebSecurityFinding.status != "RESOLVED")
            .group_by(WebSecurityFinding.endpoint)
            .order_by(func.count(WebSecurityFinding.id).desc())
            .limit(limit)
        )
        rows = self.session.execute(stmt).all()
        return [
            {
                "endpoint": row[0],
                "findings_count": row[1],
                "severity": row[2].value if hasattr(row[2], "value") else str(row[2]),
            }
            for row in rows
        ]

    def get_statistics(self) -> dict:
        total = self.session.execute(select(func.count(WebSecurityFinding.id))).scalar_one()
        critical = (
            self.session.execute(
                select(func.count(WebSecurityFinding.id)).where(
                    WebSecurityFinding.severity == RiskLevel.CRITICAL,
                    WebSecurityFinding.status != "RESOLVED",
                )
            ).scalar_one()
            or 0
        )
        active = (
            self.session.execute(
                select(func.count(WebSecurityFinding.id)).where(WebSecurityFinding.status != "RESOLVED")
            ).scalar_one()
            or 0
        )
        return {
            "total_findings": total,
            "active_findings": active,
            "critical_findings": critical,
        }
