"""User model — analyst/admin accounts. Auth logic itself belongs to Part 4."""

from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import Boolean, Index, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel, SoftDeleteMixin
from app.models.enums import UserRole
from app.models.sa_types import user_role_enum

if TYPE_CHECKING:
    from app.models.alert import Alert
    from app.models.incident import Incident
    from app.models.notification import Notification
    from app.models.report import Report
    from app.models.security_log import SecurityLog


class User(BaseModel, SoftDeleteMixin):
    """A SOC analyst, manager, admin, or viewer account."""

    __tablename__ = "users"
    __table_args__ = (
        Index("ix_users_username", "username", unique=True),
        Index("ix_users_email", "email", unique=True),
    )

    username: Mapped[str] = mapped_column(String(50), nullable=False)
    email: Mapped[str] = mapped_column(String(255), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    first_name: Mapped[str] = mapped_column(String(100), nullable=False)
    last_name: Mapped[str] = mapped_column(String(100), nullable=False)
    role: Mapped[UserRole] = mapped_column(
        user_role_enum,
        nullable=False,
        default=UserRole.ANALYST,
    )
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # --- Relationships (this side is the "one" in each one-to-many) ---
    uploaded_logs: Mapped[list["SecurityLog"]] = relationship(
        back_populates="uploaded_by", foreign_keys="SecurityLog.uploaded_by_id"
    )
    assigned_alerts: Mapped[list["Alert"]] = relationship(
        back_populates="assigned_to", foreign_keys="Alert.assigned_to_id"
    )
    owned_incidents: Mapped[list["Incident"]] = relationship(
        back_populates="owner", foreign_keys="Incident.owner_id"
    )
    generated_reports: Mapped[list["Report"]] = relationship(
        back_populates="generated_by", foreign_keys="Report.generated_by_id"
    )
    notifications: Mapped[list["Notification"]] = relationship(
        back_populates="recipient", foreign_keys="Notification.recipient_id"
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r} role={self.role.value}>"
