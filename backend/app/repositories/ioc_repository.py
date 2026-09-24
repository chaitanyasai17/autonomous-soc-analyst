"""IOCRepository — database repository for Indicators of Compromise (Part 9)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session, joinedload

from app.models.ioc_record import IOCRecord
from app.repositories.base import BaseRepository


class IOCRepository(BaseRepository[IOCRecord]):
    def __init__(self, session: Session):
        super().__init__(IOCRecord, session)

    def get_by_type_and_value(self, ioc_type: str, value: str) -> IOCRecord | None:
        stmt = select(IOCRecord).where(
            IOCRecord.ioc_type == ioc_type.strip().lower(),
            IOCRecord.value == value.strip(),
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def upsert_ioc(
        self,
        ioc_type: str,
        value: str,
        source: str,
        confidence: float = 1.0,
        description: str | None = None,
        related_alert_id: uuid.UUID | None = None,
        related_incident_id: uuid.UUID | None = None,
        tags: list | None = None,
    ) -> IOCRecord:
        clean_type = ioc_type.strip().lower()
        clean_val = value.strip()
        now = datetime.now()

        existing = self.get_by_type_and_value(clean_type, clean_val)
        if existing:
            existing.last_seen = now
            existing.confidence = max(existing.confidence, confidence)
            if description and not existing.description:
                existing.description = description
            if related_alert_id:
                existing.related_alert_id = related_alert_id
            if related_incident_id:
                existing.related_incident_id = related_incident_id
            self.session.commit()
            return existing

        record = IOCRecord(
            id=uuid.uuid4(),
            ioc_type=clean_type,
            value=clean_val,
            source=source,
            confidence=confidence,
            first_seen=now,
            last_seen=now,
            related_alert_id=related_alert_id,
            related_incident_id=related_incident_id,
            description=description,
            tags=tags or [],
        )
        self.session.add(record)
        self.session.commit()
        return record

    def list_iocs(
        self,
        ioc_type: str | None = None,
        source: str | None = None,
        search: str | None = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[IOCRecord], int]:
        stmt = select(IOCRecord).options(joinedload(IOCRecord.alert), joinedload(IOCRecord.incident))
        count_stmt = select(func.count(IOCRecord.id))

        if ioc_type:
            stmt = stmt.where(IOCRecord.ioc_type == ioc_type.strip().lower())
            count_stmt = count_stmt.where(IOCRecord.ioc_type == ioc_type.strip().lower())
        if source:
            stmt = stmt.where(IOCRecord.source == source.strip())
            count_stmt = count_stmt.where(IOCRecord.source == source.strip())
        if search:
            pattern = f"%{search.strip()}%"
            stmt = stmt.where(IOCRecord.value.ilike(pattern) | IOCRecord.description.ilike(pattern))
            count_stmt = count_stmt.where(IOCRecord.value.ilike(pattern) | IOCRecord.description.ilike(pattern))

        total = self.session.execute(count_stmt).scalar_one()
        stmt = stmt.order_by(IOCRecord.last_seen.desc()).offset(skip).limit(limit)
        items = self.session.execute(stmt).scalars().all()
        return items, total

    def get_statistics(self) -> dict:
        total = self.session.execute(select(func.count(IOCRecord.id))).scalar_one()
        type_counts = self.session.execute(
            select(IOCRecord.ioc_type, func.count(IOCRecord.id)).group_by(IOCRecord.ioc_type)
        ).all()
        by_type = {row[0]: row[1] for row in type_counts}
        return {
            "total_iocs": total,
            "by_type": by_type,
        }
