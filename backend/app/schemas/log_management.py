"""Log Management schemas — bulk operations and statistics (Part 7)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import Field

from app.models.enums import ProcessingStatus
from app.schemas.base import BaseSchema

_MAX_BULK_IDS = 200


class BulkLogIdsRequest(BaseSchema):
    """Shared request body shape for every bulk operation."""

    log_ids: list[uuid.UUID] = Field(min_length=1, max_length=_MAX_BULK_IDS)


class BulkReparseRequest(BulkLogIdsRequest):
    force: bool = Field(
        default=True,
        description="If true, discard any previously parsed records for each file before re-parsing.",
    )


class BulkItemResult(BaseSchema):
    """Outcome of one item within a bulk operation."""

    id: uuid.UUID
    success: bool
    message: str


class BulkOperationSummary(BaseSchema):
    """
    Standard bulk-operation response envelope.

    Bulk operations here use partial-success semantics, not all-or-nothing
    atomicity: each item's authorization/business-rule check and its
    database mutation are individually safe (existing per-item transactions
    from UploadService/ParserService), but the batch as a whole does not
    roll back earlier successes if a later item fails — this is the
    standard pattern for bulk APIs with per-item authorization and external
    side effects (disk I/O), matching how e.g. cloud provider batch-delete
    APIs behave, and avoids the far worse alternative of trying to "undo" a
    completed file deletion if a later, unrelated item fails.
    """

    total: int
    succeeded: int
    failed: int
    results: list[BulkItemResult]

    @classmethod
    def build(cls, results: list[BulkItemResult]) -> "BulkOperationSummary":
        succeeded = sum(1 for r in results if r.success)
        return cls(total=len(results), succeeded=succeeded, failed=len(results) - succeeded, results=results)


class BulkStatusItem(BaseSchema):
    """One entry in a bulk status lookup response."""

    id: uuid.UUID
    found: bool
    processing_status: ProcessingStatus | None = None
    parsed_record_count: int | None = None


class LogStatistics(BaseSchema):
    """Aggregate statistics over a user's visible logs (or all logs, for LOG_READ_ANY roles)."""

    total_uploads: int
    total_file_size_bytes: int
    total_parsed_records: int
    by_processing_status: dict[str, int]
    by_log_source: dict[str, int]
    last_upload_at: datetime | None
