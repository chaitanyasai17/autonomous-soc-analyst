"""
Base model and shared mixins.

Every ORM model in app/models/ subclasses `BaseModel`, which supplies:
    - id (UUID primary key)
    - created_at / updated_at (UTC, server-managed)

`SoftDeleteMixin` is opt-in and applied only to models where hiding a record
from active views (while retaining it for audit/history) is meaningful:
User, Alert, Incident, Report. Append-only/audit-trail data (SecurityLog,
ParsedLog, SigmaDetection, MitreTechnique, RiskAssessment, Notification) is
never soft-deleted — those rows represent immutable historical facts.
"""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base


class BaseModel(Base):
    """Abstract base class providing a UUID primary key and UTC timestamps."""

    __abstract__ = True

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class SoftDeleteMixin:
    """Opt-in mixin adding a nullable `deleted_at` marker for soft deletes."""

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None
