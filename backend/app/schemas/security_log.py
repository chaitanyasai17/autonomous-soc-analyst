"""SecurityLog response schemas (API boundary DTOs — see app/models/security_log.py for the ORM entity)."""

from __future__ import annotations

import uuid
from datetime import datetime

from app.models.enums import LogSource, ProcessingStatus
from app.schemas.base import BaseSchema


class SecurityLogOut(BaseSchema):
    """
    Public representation of an uploaded log file.

    `storage_path` is deliberately NOT included — filesystem layout must
    never be exposed to clients (see Part 5 security requirements).
    """

    id: uuid.UUID
    filename: str
    original_filename: str
    log_source: LogSource
    file_type: str
    file_size: int
    mime_type: str
    checksum_sha256: str
    uploaded_by_id: uuid.UUID
    upload_time: datetime
    processing_status: ProcessingStatus
    event_count: int = 0
    created_at: datetime
    updated_at: datetime
