"""
Notification repository — database queries for in-app analyst alerts.
"""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from app.models.notification import Notification
from app.repositories.base import BaseRepository


class NotificationRepository(BaseRepository[Notification]):
    def __init__(self, session: Session):
        super().__init__(Notification, session)

    def list_for_user(
        self,
        recipient_id: uuid.UUID,
        unread_only: bool = False,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[Sequence[Notification], int]:
        stmt = select(Notification).where(Notification.recipient_id == recipient_id)
        count_stmt = select(func.count(Notification.id)).where(Notification.recipient_id == recipient_id)

        if unread_only:
            stmt = stmt.where(Notification.is_read.is_(False))
            count_stmt = count_stmt.where(Notification.is_read.is_(False))

        total = self.session.execute(count_stmt).scalar_one()
        stmt = stmt.order_by(Notification.sent_at.desc()).offset(skip).limit(limit)
        items = self.session.execute(stmt).scalars().all()
        return items, total

    def count_unread(self, recipient_id: uuid.UUID) -> int:
        stmt = select(func.count(Notification.id)).where(
            Notification.recipient_id == recipient_id, Notification.is_read.is_(False)
        )
        return self.session.execute(stmt).scalar_one()

    def mark_all_read(self, recipient_id: uuid.UUID) -> int:
        stmt = (
            update(Notification)
            .where(Notification.recipient_id == recipient_id, Notification.is_read.is_(False))
            .values(is_read=True)
        )
        res = self.session.execute(stmt)
        self.session.commit()
        return res.rowcount
