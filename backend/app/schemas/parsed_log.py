"""Parsed log and parse-result response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field

from app.models.enums import ProcessingStatus, RiskLevel
from app.schemas.base import BaseSchema

_MAX_ERRORS_IN_RESPONSE = 50


class ParsedLogOut(BaseSchema):
    """Public representation of a single normalized log entry."""

    id: uuid.UUID
    security_log_id: uuid.UUID
    timestamp: datetime
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    username: str | None
    hostname: str | None
    event_id: str | None
    event_type: str
    severity: RiskLevel
    protocol: str | None
    action: str | None
    message: str | None
    raw_log: str
    created_at: datetime


class ParseResultSummary(BaseSchema):
    """Returned by the parse/reparse endpoints — outcome of one parse job."""

    security_log_id: uuid.UUID
    processing_status: ProcessingStatus
    entries_created: int
    error_count: int
    errors: list[str] = Field(default_factory=list)
    errors_truncated: bool = False

    @classmethod
    def build(
        cls,
        *,
        security_log_id: uuid.UUID,
        processing_status: ProcessingStatus,
        entries_created: int,
        errors: list[str],
    ) -> "ParseResultSummary":
        """Cap the errors list returned to the client so a badly-formed file
        can't produce a multi-thousand-line response payload."""
        return cls(
            security_log_id=security_log_id,
            processing_status=processing_status,
            entries_created=entries_created,
            error_count=len(errors),
            errors=errors[:_MAX_ERRORS_IN_RESPONSE],
            errors_truncated=len(errors) > _MAX_ERRORS_IN_RESPONSE,
        )


class ParsingStatusOut(BaseSchema):
    """Lightweight status check — avoids pulling the full parsed record set."""

    security_log_id: uuid.UUID
    processing_status: ProcessingStatus
    parsed_record_count: int
