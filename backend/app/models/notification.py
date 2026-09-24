"""Notification model — an in-app notification delivered to a User."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, DateTime, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel
from app.models.enums import NotificationType
from app.models.sa_types import notification_type_enum

if TYPE_CHECKING:
    from app.models.user import User


class Notification(BaseModel):
    """A single notification delivered to a User (email/in-app dispatch is Part 14)."""

    __tablename__ = "notifications"
    __table_args__ = (
        Index("ix_notifications_is_read", "is_read"),
        Index("ix_notifications_sent_at", "sent_at"),
    )

    recipient_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    notification_type: Mapped[NotificationType] = mapped_column(
        notification_type_enum, nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    message: Mapped[str] = mapped_column(Text, nullable=False)
    is_read: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    sent_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    # --- Relationships ---
    recipient: Mapped["User"] = relationship(
        back_populates="notifications", foreign_keys=[recipient_id]
    )

    def __repr__(self) -> str:
        return f"<Notification id={self.id} type={self.notification_type.value} is_read={self.is_read}>"
