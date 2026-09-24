"""
Alert repository — database operations for security alerts.
"""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.models.alert import Alert
from app.models.enums import AlertStatus, RiskLevel
from app.repositories.base import BaseRepository


class AlertRepository(BaseRepository[Alert]):
    def __init__(self, session: Session):
        super().__init__(Alert, session)

    def get_with_relations(self, alert_id: uuid.UUID) -> Alert | None:
        stmt = (
            select(Alert)
            .options(
                joinedload(Alert.risk_assessment),
                joinedload(Alert.incident),
                joinedload(Alert.assigned_to),
            )
            .where(Alert.id == alert_id, Alert.deleted_at.is_(None))
        )
        return self.session.execute(stmt).scalars().first()

    def search(
        self,
        status: AlertStatus | None = None,
        severity: RiskLevel | None = None,
        assigned_to_id: uuid.UUID | None = None,
        incident_id: uuid.UUID | None = None,
        search_query: str | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[Alert], int]:
        stmt = select(Alert).where(Alert.deleted_at.is_(None))
        count_stmt = select(func.count(Alert.id)).where(Alert.deleted_at.is_(None))

        if status is not None:
            stmt = stmt.where(Alert.status == status)
            count_stmt = count_stmt.where(Alert.status == status)

        if severity is not None:
            stmt = stmt.where(Alert.severity == severity)
            count_stmt = count_stmt.where(Alert.severity == severity)

        if assigned_to_id is not None:
            stmt = stmt.where(Alert.assigned_to_id == assigned_to_id)
            count_stmt = count_stmt.where(Alert.assigned_to_id == assigned_to_id)

        if incident_id is not None:
            stmt = stmt.where(Alert.incident_id == incident_id)
            count_stmt = count_stmt.where(Alert.incident_id == incident_id)

        if search_query:
            term = f"%{search_query.strip().lower()}%"
            filter_clause = func.lower(Alert.title).like(term) | func.lower(Alert.description).like(term)
            stmt = stmt.where(filter_clause)
            count_stmt = count_stmt.where(filter_clause)

        total = self.session.execute(count_stmt).scalar_one()
        stmt = (
            stmt.options(
                joinedload(Alert.assigned_to),
                joinedload(Alert.risk_assessment),
            )
            .order_by(Alert.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        items = self.session.execute(stmt).scalars().all()
        return items, total

    def get_statistics(self) -> dict:
        total = self.session.execute(
            select(func.count(Alert.id)).where(Alert.deleted_at.is_(None))
        ).scalar_one()

        by_severity: dict[str, int] = {level.value: 0 for level in RiskLevel}
        sev_counts = self.session.execute(
            select(Alert.severity, func.count(Alert.id))
            .where(Alert.deleted_at.is_(None))
            .group_by(Alert.severity)
        ).all()
        for sev, count in sev_counts:
            sev_val = sev.value if hasattr(sev, "value") else str(sev)
            by_severity[sev_val] = count

        by_status: dict[str, int] = {st.value: 0 for st in AlertStatus}
        status_counts = self.session.execute(
            select(Alert.status, func.count(Alert.id))
            .where(Alert.deleted_at.is_(None))
            .group_by(Alert.status)
        ).all()
        for st, count in status_counts:
            st_val = st.value if hasattr(st, "value") else str(st)
            by_status[st_val] = count

        return {
            "total_alerts": total,
            "by_severity": by_severity,
            "by_status": by_status,
            "critical_open": self.session.execute(
                select(func.count(Alert.id)).where(
                    Alert.deleted_at.is_(None),
                    Alert.severity == RiskLevel.CRITICAL,
                    Alert.status.in_([AlertStatus.OPEN, AlertStatus.IN_PROGRESS]),
                )
            ).scalar_one(),
        }
