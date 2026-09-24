"""Audit Log Pydantic schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, Optional

from app.schemas.base import BaseSchema


class AuditLogOut(BaseSchema):
    id: uuid.UUID
    timestamp: datetime
    user_id: Optional[uuid.UUID] = None
    username: Optional[str] = None
    role: Optional[str] = None
    action: str
    object_type: Optional[str] = None
    object_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    status: str
    created_at: datetime


class AuditLogCreate(BaseSchema):
    action: str
    object_type: Optional[str] = None
    object_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    ip_address: Optional[str] = None
    status: str = "SUCCESS"
