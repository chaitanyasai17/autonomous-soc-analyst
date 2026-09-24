"""
Notification Pydantic schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from app.models.enums import NotificationType
from app.schemas.base import BaseSchema


class NotificationOut(BaseSchema):
    id: uuid.UUID
    recipient_id: uuid.UUID
    notification_type: NotificationType
    title: str
    message: str
    is_read: bool
    sent_at: datetime


class UnreadCountOut(BaseSchema):
    unread_count: int
