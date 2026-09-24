"""
Incident repository — persistence, query operations, and number sequencing for security investigations.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.models.alert import Alert
from app.models.enums import IncidentStatus, RiskLevel
from app.models.incident import Incident
from app.repositories.base import BaseRepository
from app.utils.datetime_utils import utc_now


class IncidentRepository(BaseRepository[Incident]):
    def __init__(self, session: Session):
        super().__init__(Incident, session)

    def next_incident_number(self) -> str:
        year = utc_now().year
        prefix = f"INC-{year}-"
        stmt = (
            select(func.count(Incident.id))
            .where(Incident.incident_number.like(f"{prefix}%"))
        )
        current_count = self.session.execute(stmt).scalar_one()
        pending = sum(
            1 for obj in self.session.new
            if isinstance(obj, Incident) and getattr(obj, "incident_number", "").startswith(prefix)
        )
        return f"{prefix}{current_count + pending + 1:04d}"

    def get_with_relations(self, incident_id: uuid.UUID) -> Incident | None:
        stmt = (
            select(Incident)
            .options(
                joinedload(Incident.owner),
                joinedload(Incident.alerts).joinedload(Alert.risk_assessment),
                joinedload(Incident.alerts).joinedload(Alert.assigned_to),
            )
            .where(Incident.id == incident_id, Incident.deleted_at.is_(None))
        )
        return self.session.execute(stmt).scalars().unique().first()

    def get_by_number(self, incident_number: str) -> Incident | None:
        stmt = (
            select(Incident)
            .options(
                joinedload(Incident.owner),
                joinedload(Incident.alerts),
            )
            .where(
                func.lower(Incident.incident_number) == incident_number.strip().lower(),
                Incident.deleted_at.is_(None),
            )
        )
        return self.session.execute(stmt).scalars().first()

    def search(
        self,
        status: IncidentStatus | None = None,
        priority: RiskLevel | None = None,
        owner_id: uuid.UUID | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[Incident], int]:
        stmt = select(Incident).where(Incident.deleted_at.is_(None))
        count_stmt = select(func.count(Incident.id)).where(Incident.deleted_at.is_(None))

        if status is not None:
            stmt = stmt.where(Incident.status == status)
            count_stmt = count_stmt.where(Incident.status == status)

        if priority is not None:
            stmt = stmt.where(Incident.priority == priority)
            count_stmt = count_stmt.where(Incident.priority == priority)

        if owner_id is not None:
            stmt = stmt.where(Incident.owner_id == owner_id)
            count_stmt = count_stmt.where(Incident.owner_id == owner_id)

        total = self.session.execute(count_stmt).scalar_one()
        stmt = (
            stmt.options(
                joinedload(Incident.owner),
                joinedload(Incident.alerts).joinedload(Alert.risk_assessment),
                joinedload(Incident.alerts).joinedload(Alert.assigned_to),
            )
            .order_by(Incident.opened_at.desc())
            .offset(skip)
            .limit(limit)
        )
        items = self.session.execute(stmt).scalars().unique().all()
        return items, total

    def get_statistics(self) -> dict:
        total = self.session.execute(
            select(func.count(Incident.id)).where(Incident.deleted_at.is_(None))
        ).scalar_one()

        by_status: dict[str, int] = {st.value: 0 for st in IncidentStatus}
        status_counts = self.session.execute(
            select(Incident.status, func.count(Incident.id))
            .where(Incident.deleted_at.is_(None))
            .group_by(Incident.status)
        ).all()
        for st, count in status_counts:
            st_val = st.value if hasattr(st, "value") else str(st)
            by_status[st_val] = count

        by_priority: dict[str, int] = {p.value: 0 for p in RiskLevel}
        prio_counts = self.session.execute(
            select(Incident.priority, func.count(Incident.id))
            .where(Incident.deleted_at.is_(None))
            .group_by(Incident.priority)
        ).all()
        for p, count in prio_counts:
            p_val = p.value if hasattr(p, "value") else str(p)
            by_priority[p_val] = count

        open_active = (
            by_status.get(IncidentStatus.OPEN.value, 0)
            + by_status.get(IncidentStatus.INVESTIGATING.value, 0)
            + by_status.get(IncidentStatus.CONTAINED.value, 0)
        )

        return {
            "total_incidents": total,
            "open_active_incidents": open_active,
            "by_status": by_status,
            "by_priority": by_priority,
        }
