"""
Notification Service — manages in-app analyst alerts and read states.
"""

from __future__ import annotations

import logging
import uuid
from typing import Sequence

from app.core.exceptions import ForbiddenError, NotFoundError
from app.models.enums import NotificationType
from app.models.notification import Notification
from app.repositories.notification_repository import NotificationRepository
from app.schemas.notification import NotificationOut, UnreadCountOut
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)


class NotificationService:
    def __init__(self, notification_repository: NotificationRepository):
        self.notification_repository = notification_repository

    def create_notification(
        self,
        recipient_id: uuid.UUID,
        title: str,
        message: str,
        notification_type: NotificationType | str = NotificationType.SYSTEM,
    ) -> Notification:
        if isinstance(notification_type, str):
            try:
                nt = NotificationType(notification_type)
            except ValueError:
                nt = NotificationType.SYSTEM
        else:
            nt = notification_type

        notification = Notification(
            id=uuid.uuid4(),
            recipient_id=recipient_id,
            notification_type=nt,
            title=title,
            message=message,
            is_read=False,
            sent_at=utc_now(),
        )
        self.notification_repository.create(notification)
        return notification

    def list_user_notifications(
        self,
        recipient_id: uuid.UUID,
        unread_only: bool = False,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[NotificationOut], int]:
        items, total = self.notification_repository.list_for_user(
            recipient_id=recipient_id, unread_only=unread_only, skip=skip, limit=limit
        )
        out = [
            NotificationOut(
                id=n.id,
                recipient_id=n.recipient_id,
                notification_type=n.notification_type,
                title=n.title,
                message=n.message,
                is_read=n.is_read,
                sent_at=n.sent_at,
            )
            for n in items
        ]
        return out, total

    def get_unread_count(self, recipient_id: uuid.UUID) -> UnreadCountOut:
        count = self.notification_repository.count_unread(recipient_id)
        return UnreadCountOut(unread_count=count)

    def mark_read(self, notification_id: uuid.UUID, requesting_user_id: uuid.UUID) -> NotificationOut:
        notification = self.notification_repository.get_by_id(notification_id)
        if not notification:
            raise NotFoundError(f"Notification '{notification_id}' not found.")
        if notification.recipient_id != requesting_user_id:
            raise ForbiddenError("Cannot mark another user's notification as read.")

        notification.is_read = True
        self.notification_repository.session.commit()
        return NotificationOut(
            id=notification.id,
            recipient_id=notification.recipient_id,
            notification_type=notification.notification_type,
            title=notification.title,
            message=notification.message,
            is_read=notification.is_read,
            sent_at=notification.sent_at,
        )

    def mark_all_read(self, recipient_id: uuid.UUID) -> int:
        return self.notification_repository.mark_all_read(recipient_id)
