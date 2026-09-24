"""SecurityLog repository — data access only, no business rules (see services/upload_service.py)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Sequence

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.enums import LogSource, ProcessingStatus
from app.models.parsed_log import ParsedLog
from app.models.security_log import SecurityLog
from app.models.user import User
from app.repositories.base import BaseRepository


class SecurityLogRepository(BaseRepository[SecurityLog]):
    """Repository encapsulating all direct queries against the security_logs table."""

    def __init__(self, db: Session):
        super().__init__(model=SecurityLog, db=db)

    def get_by_checksum(self, checksum_sha256: str) -> SecurityLog | None:
        """Find an existing upload with identical content (informational — not used to block uploads)."""
        stmt = select(SecurityLog).where(SecurityLog.checksum_sha256 == checksum_sha256)
        return self.db.execute(stmt).scalars().first()

    _SORTABLE_FIELDS = {
        "upload_time": SecurityLog.upload_time,
        "created_at": SecurityLog.created_at,
        "original_filename": SecurityLog.original_filename,
        "file_size": SecurityLog.file_size,
    }

    def get_by_id(self, record_id: Any) -> SecurityLog | None:
        item = super().get_by_id(record_id)
        if item:
            count = self.db.execute(
                select(func.count(ParsedLog.id)).where(ParsedLog.security_log_id == item.id)
            ).scalar_one()
            item.event_count = count
        return item

    def search(
        self,
        *,
        uploaded_by_id: uuid.UUID | None = None,
        uploaded_by_username: str | None = None,
        log_source: LogSource | None = None,
        processing_status: ProcessingStatus | None = None,
        file_type: str | None = None,
        upload_date_from: datetime | None = None,
        upload_date_to: datetime | None = None,
        file_size_min: int | None = None,
        file_size_max: int | None = None,
        search: str | None = None,
        skip: int = 0,
        limit: int = 20,
        sort_by: str = "upload_time",
        sort_order: str = "desc",
    ) -> tuple[Sequence[SecurityLog], int]:
        """Return (page_of_logs, total_matching_count) for the given filters.

        `uploaded_by_id=None` means "no ownership restriction" — callers
        (UploadService) pass a concrete id to scope results to one uploader
        when the requesting user lacks LOG_READ_ANY.

        Part 7 additions: date range, file size range, file type, and
        uploaded-by-username filters, plus a "event_count" sort option
        (records parsed from each file) implemented via a correlated scalar
        subquery in ORDER BY only — this adds zero extra queries regardless
        of page size (no N+1), since it never changes the SELECTed columns
        or requires a GROUP BY on the base query.
        """
        conditions = []
        needs_user_join = uploaded_by_username is not None

        base_stmt = select(SecurityLog)
        count_stmt = select(func.count()).select_from(SecurityLog)

        if needs_user_join:
            base_stmt = base_stmt.join(User, SecurityLog.uploaded_by_id == User.id)
            count_stmt = count_stmt.join(User, SecurityLog.uploaded_by_id == User.id)
            conditions.append(User.username.ilike(f"%{uploaded_by_username}%"))

        if uploaded_by_id is not None:
            conditions.append(SecurityLog.uploaded_by_id == uploaded_by_id)
        if log_source is not None:
            conditions.append(SecurityLog.log_source == log_source)
        if processing_status is not None:
            conditions.append(SecurityLog.processing_status == processing_status)
        if file_type is not None:
            conditions.append(SecurityLog.file_type == file_type)
        if upload_date_from is not None:
            conditions.append(SecurityLog.upload_time >= upload_date_from)
        if upload_date_to is not None:
            conditions.append(SecurityLog.upload_time <= upload_date_to)
        if file_size_min is not None:
            conditions.append(SecurityLog.file_size >= file_size_min)
        if file_size_max is not None:
            conditions.append(SecurityLog.file_size <= file_size_max)
        if search:
            like_pattern = f"%{search}%"
            conditions.append(
                or_(
                    SecurityLog.filename.ilike(like_pattern),
                    SecurityLog.original_filename.ilike(like_pattern),
                )
            )

        base_stmt = base_stmt.where(*conditions)
        count_stmt = count_stmt.where(*conditions)

        if sort_by == "event_count":
            event_count_subquery = (
                select(func.count(ParsedLog.id))
                .where(ParsedLog.security_log_id == SecurityLog.id)
                .scalar_subquery()
            )
            order_clause = (
                event_count_subquery.desc() if sort_order == "desc" else event_count_subquery.asc()
            )
        else:
            sort_column = self._SORTABLE_FIELDS.get(sort_by, SecurityLog.upload_time)
            order_clause = sort_column.desc() if sort_order == "desc" else sort_column.asc()

        page_stmt = base_stmt.order_by(order_clause).offset(skip).limit(limit)

        items = list(self.db.execute(page_stmt).scalars().all())
        total = self.db.execute(count_stmt).scalar_one()

        if items:
            log_ids = [item.id for item in items]
            count_rows = self.db.execute(
                select(ParsedLog.security_log_id, func.count(ParsedLog.id))
                .where(ParsedLog.security_log_id.in_(log_ids))
                .group_by(ParsedLog.security_log_id)
            ).all()
            counts_by_id = {row[0]: row[1] for row in count_rows}
            for item in items:
                setattr(item, "event_count", counts_by_id.get(item.id, 0))

        return items, total

    # --- Bulk status (Part 7) ---

    def get_bulk_status(
        self, log_ids: Sequence[uuid.UUID], uploaded_by_id: uuid.UUID | None = None
    ) -> list[tuple[SecurityLog, int]]:
        """
        Return (SecurityLog, parsed_record_count) for every requested id the
        caller may see, in a single query — used by the bulk-status endpoint
        so checking N ids never costs N queries.
        """
        stmt = (
            select(SecurityLog, func.count(ParsedLog.id))
            .outerjoin(ParsedLog, ParsedLog.security_log_id == SecurityLog.id)
            .where(SecurityLog.id.in_(log_ids))
            .group_by(SecurityLog.id)
        )
        if uploaded_by_id is not None:
            stmt = stmt.where(SecurityLog.uploaded_by_id == uploaded_by_id)
        return [(row[0], row[1]) for row in self.db.execute(stmt).all()]

    # --- Statistics (Part 7) ---

    def get_statistics(self, uploaded_by_id: uuid.UUID | None = None) -> dict:
        """
        A handful of small aggregate queries (bounded by the number of
        distinct enum values, not row count) — not a per-row cost, so this
        remains cheap regardless of how many logs exist.
        """
        conditions = []
        if uploaded_by_id is not None:
            conditions.append(SecurityLog.uploaded_by_id == uploaded_by_id)

        total_uploads = self.db.execute(
            select(func.count()).select_from(SecurityLog).where(*conditions)
        ).scalar_one()

        total_file_size = self.db.execute(
            select(func.coalesce(func.sum(SecurityLog.file_size), 0)).where(*conditions)
        ).scalar_one()

        status_rows = self.db.execute(
            select(SecurityLog.processing_status, func.count())
            .where(*conditions)
            .group_by(SecurityLog.processing_status)
        ).all()
        by_processing_status = {status.value: count for status, count in status_rows}

        source_rows = self.db.execute(
            select(SecurityLog.log_source, func.count())
            .where(*conditions)
            .group_by(SecurityLog.log_source)
        ).all()
        by_log_source = {source.value: count for source, count in source_rows}

        parsed_count_stmt = (
            select(func.count())
            .select_from(ParsedLog)
            .join(SecurityLog, ParsedLog.security_log_id == SecurityLog.id)
            .where(*conditions)
        )
        total_parsed_records = self.db.execute(parsed_count_stmt).scalar_one()

        last_upload_at = self.db.execute(
            select(func.max(SecurityLog.upload_time)).where(*conditions)
        ).scalar_one()

        return {
            "total_uploads": total_uploads,
            "total_file_size_bytes": int(total_file_size),
            "total_parsed_records": total_parsed_records,
            "by_processing_status": by_processing_status,
            "by_log_source": by_log_source,
            "last_upload_at": last_upload_at,
        }

