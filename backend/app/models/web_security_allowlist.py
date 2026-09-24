"""WebSecurityAllowlist model — target allowlist for authorized web security testing."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, Index, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import BaseModel

if TYPE_CHECKING:
    from app.models.user import User


class WebSecurityAllowlist(BaseModel):
    """Administrator-controlled allowlist entry for authorized web security scans."""

    __tablename__ = "web_security_allowlist"
    __table_args__ = (
        Index("ix_web_security_allowlist_pattern", "pattern", unique=True),
        Index("ix_web_security_allowlist_is_active", "is_active"),
    )

    pattern: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_username: Mapped[str | None] = mapped_column(String(100), nullable=True)

    created_by: Mapped["User | None"] = relationship(foreign_keys=[created_by_id])

    def __repr__(self) -> str:
        return f"<WebSecurityAllowlist id={self.id} pattern={self.pattern!r} active={self.is_active}>"
