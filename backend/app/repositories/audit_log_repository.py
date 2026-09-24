"""
AuditLogRepository — queries and persists immutable operational audit records.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.models.audit_log import AuditLog
from app.models.user import User
from app.repositories.base import BaseRepository


class AuditLogRepository(BaseRepository[AuditLog]):
    def __init__(self, db: Session):
        super().__init__(model=AuditLog, db=db)

    def log(
        self,
        action: str,
        user: User | None = None,
        username: str | None = None,
        role: str | None = None,
        object_type: str | None = None,
        object_id: str | None = None,
        details: Dict[str, Any] | None = None,
        ip_address: str | None = None,
        status: str = "SUCCESS",
    ) -> AuditLog:
        """Create and commit an immutable audit log entry."""
        user_id = user.id if user else None
        user_name = user.username if user else username
        user_role = user.role.value if (user and hasattr(user.role, "value")) else (user.role if user else role)

        record = AuditLog(
            action=action.upper(),
            user_id=user_id,
            username=user_name,
            role=user_role,
            object_type=object_type.upper() if object_type else None,
            object_id=str(object_id) if object_id else None,
            details=details,
            ip_address=ip_address,
            status=status.upper(),
            timestamp=datetime.now(timezone.utc),
        )
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record

    def search(
        self,
        action: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
        username: Optional[str] = None,
        object_type: Optional[str] = None,
        object_id: Optional[str] = None,
        status: Optional[str] = None,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
        skip: int = 0,
        limit: int = DEFAULT_PAGE_SIZE,
    ) -> Tuple[List[AuditLog], int]:
        """Search and paginate audit logs."""
        query = select(AuditLog)

        if action:
            query = query.where(AuditLog.action == action.upper())
        if user_id:
            query = query.where(AuditLog.user_id == user_id)
        if username:
            query = query.where(AuditLog.username.ilike(f"%{username}%"))
        if object_type:
            query = query.where(AuditLog.object_type == object_type.upper())
        if object_id:
            query = query.where(AuditLog.object_id == str(object_id))
        if status:
            query = query.where(AuditLog.status == status.upper())
        if date_from:
            query = query.where(AuditLog.timestamp >= date_from)
        if date_to:
            query = query.where(AuditLog.timestamp <= date_to)

        # Count total
        count_query = select(func.count()).select_from(query.subquery())
        total = self.db.execute(count_query).scalar_one()

        # Paginate with chronological desc sort
        limit_bounded = min(limit, MAX_PAGE_SIZE)
        query = query.order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit_bounded)
        items = list(self.db.execute(query).scalars().all())

        return items, total
