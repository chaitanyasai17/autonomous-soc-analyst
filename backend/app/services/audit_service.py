"""
AuditService — Business logic and audit trail generation for SOC operations.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from app.core.exceptions import NotFoundError
from app.models.audit_log import AuditLog
from app.models.user import User
from app.repositories.audit_log_repository import AuditLogRepository


class AuditService:
    def __init__(self, audit_log_repository: AuditLogRepository):
        self.repo = audit_log_repository

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
        return self.repo.log(
            action=action,
            user=user,
            username=username,
            role=role,
            object_type=object_type,
            object_id=object_id,
            details=details,
            ip_address=ip_address,
            status=status,
        )

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
        limit: int = 20,
    ) -> Tuple[List[AuditLog], int]:
        return self.repo.search(
            action=action,
            user_id=user_id,
            username=username,
            object_type=object_type,
            object_id=object_id,
            status=status,
            date_from=date_from,
            date_to=date_to,
            skip=skip,
            limit=limit,
        )

    def get_by_id(self, log_id: uuid.UUID) -> AuditLog:
        item = self.repo.get_by_id(log_id)
        if not item:
            raise NotFoundError(f"Audit log entry '{log_id}' not found.")
        return item
