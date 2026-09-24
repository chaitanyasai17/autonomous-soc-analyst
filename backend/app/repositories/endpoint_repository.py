"""Endpoint repository — database persistence for enrolled SOC endpoints."""

from __future__ import annotations

import uuid
from typing import Sequence, Tuple

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session, joinedload

from app.models.endpoint import Endpoint
from app.models.enums import RiskLevel
from app.repositories.base import BaseRepository


class EndpointRepository(BaseRepository[Endpoint]):
    def __init__(self, session: Session):
        super().__init__(Endpoint, session)

    def get_by_hostname(self, hostname: str) -> Endpoint | None:
        stmt = (
            select(Endpoint)
            .options(joinedload(Endpoint.owner))
            .where(
                func.lower(Endpoint.hostname) == hostname.lower().strip(),
                Endpoint.deleted_at.is_(None),
            )
        )
        return self.session.execute(stmt).scalars().first()

    def get_with_owner(self, endpoint_id: uuid.UUID) -> Endpoint | None:
        stmt = (
            select(Endpoint)
            .options(joinedload(Endpoint.owner))
            .where(Endpoint.id == endpoint_id, Endpoint.deleted_at.is_(None))
        )
        return self.session.execute(stmt).scalars().first()

    def search(
        self,
        owner_id: uuid.UUID | None = None,
        status: str | None = None,
        risk_level: RiskLevel | None = None,
        search_query: str | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> Tuple[Sequence[Endpoint], int]:
        stmt = select(Endpoint).options(joinedload(Endpoint.owner)).where(Endpoint.deleted_at.is_(None))
        count_stmt = select(func.count(Endpoint.id)).where(Endpoint.deleted_at.is_(None))

        if owner_id is not None:
            stmt = stmt.where(Endpoint.owner_id == owner_id)
            count_stmt = count_stmt.where(Endpoint.owner_id == owner_id)

        if status is not None:
            stmt = stmt.where(Endpoint.status == status)
            count_stmt = count_stmt.where(Endpoint.status == status)

        if risk_level is not None:
            stmt = stmt.where(Endpoint.risk_level == risk_level)
            count_stmt = count_stmt.where(Endpoint.risk_level == risk_level)

        if search_query:
            term = f"%{search_query.strip()}%"
            filter_cond = or_(
                Endpoint.hostname.ilike(term),
                Endpoint.ip_address.ilike(term),
                Endpoint.operating_system.ilike(term),
            )
            stmt = stmt.where(filter_cond)
            count_stmt = count_stmt.where(filter_cond)

        total = self.session.execute(count_stmt).scalar_one()
        stmt = stmt.order_by(Endpoint.last_seen.desc()).offset(skip).limit(limit)
        items = self.session.execute(stmt).scalars().all()
        return items, total

    def count_statistics(self, owner_id: uuid.UUID | None = None) -> dict:
        stmt = select(
            func.count(Endpoint.id).label("total"),
            func.count(Endpoint.id).filter(Endpoint.status == "online").label("online"),
            func.count(Endpoint.id).filter(Endpoint.status == "offline").label("offline"),
            func.count(Endpoint.id).filter(Endpoint.status == "degraded").label("degraded"),
            func.count(Endpoint.id).filter(Endpoint.is_isolated.is_(True)).label("isolated"),
        ).where(Endpoint.deleted_at.is_(None))

        if owner_id is not None:
            stmt = stmt.where(Endpoint.owner_id == owner_id)

        row = self.session.execute(stmt).one()

        # Group by risk
        risk_stmt = select(Endpoint.risk_level, func.count(Endpoint.id)).where(Endpoint.deleted_at.is_(None))
        if owner_id is not None:
            risk_stmt = risk_stmt.where(Endpoint.owner_id == owner_id)
        risk_stmt = risk_stmt.group_by(Endpoint.risk_level)
        risk_counts = {r.value: 0 for r in RiskLevel}
        for level, count in self.session.execute(risk_stmt).all():
            risk_counts[level.value if hasattr(level, "value") else str(level)] = count

        return {
            "total_endpoints": row.total or 0,
            "online_endpoints": row.online or 0,
            "offline_endpoints": row.offline or 0,
            "degraded_endpoints": row.degraded or 0,
            "isolated_endpoints": row.isolated or 0,
            "by_risk_level": risk_counts,
        }
