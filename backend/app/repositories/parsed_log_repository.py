"""ParsedLog repository — data access only, no business rules (see services/parser_service.py)."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Sequence

from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session

from app.models.enums import LogSource, ProcessingStatus, RiskLevel
from app.models.parsed_log import ParsedLog
from app.models.security_log import SecurityLog
from app.repositories.base import BaseRepository


class ParsedLogRepository(BaseRepository[ParsedLog]):
    """Repository encapsulating all direct queries against the parsed_logs table."""

    def __init__(self, db: Session):
        super().__init__(model=ParsedLog, db=db)

    def bulk_create(self, entries: Sequence[ParsedLog]) -> None:
        """Insert many rows in one commit — used by ParserService's batched insert loop."""
        self.db.add_all(entries)
        self.db.commit()

    def delete_by_security_log_id(self, security_log_id: uuid.UUID) -> int:
        """Remove all previously-parsed records for a file (used by reparse). Returns rows deleted."""
        stmt = delete(ParsedLog).where(ParsedLog.security_log_id == security_log_id)
        result = self.db.execute(stmt)
        self.db.commit()
        return result.rowcount or 0

    def count_by_security_log_id(self, security_log_id: uuid.UUID) -> int:
        stmt = select(func.count()).select_from(ParsedLog).where(
            ParsedLog.security_log_id == security_log_id
        )
        return self.db.execute(stmt).scalar_one()

    _SORTABLE_FIELDS = {
        "timestamp": ParsedLog.timestamp,
        "created_at": ParsedLog.created_at,
        "severity": ParsedLog.severity,
        "event_type": ParsedLog.event_type,
    }

    def search(
        self,
        *,
        security_log_id: uuid.UUID | None = None,
        uploaded_by_id: uuid.UUID | None = None,
        event_type: str | None = None,
        severity: RiskLevel | None = None,
        source_ip: str | None = None,
        destination_ip: str | None = None,
        hostname: str | None = None,
        username: str | None = None,
        event_id: str | None = None,
        protocol: str | None = None,
        action: str | None = None,
        log_source: LogSource | None = None,
        processing_status: ProcessingStatus | None = None,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
        search: str | None = None,
        skip: int = 0,
        limit: int = 20,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
    ) -> tuple[Sequence[ParsedLog], int]:
        """
        Return (page_of_entries, total_matching_count).

        `uploaded_by_id`, when provided, joins to SecurityLog to scope
        results to one uploader — used for the global /parsed-logs listing
        when the requesting user lacks LOG_READ_ANY. `log_source` and
        `processing_status` (Part 7 additions) also require that same join
        since they live on the parent SecurityLog, not on ParsedLog itself;
        the join is only added when actually needed, keeping the common
        case (no parent-level filters) a single-table query.
        """
        conditions = []
        needs_join = uploaded_by_id is not None or log_source is not None or processing_status is not None

        base_stmt = select(ParsedLog)
        count_stmt = select(func.count()).select_from(ParsedLog)
        if needs_join:
            base_stmt = base_stmt.join(SecurityLog, ParsedLog.security_log_id == SecurityLog.id)
            count_stmt = count_stmt.join(SecurityLog, ParsedLog.security_log_id == SecurityLog.id)
            if uploaded_by_id is not None:
                conditions.append(SecurityLog.uploaded_by_id == uploaded_by_id)
            if log_source is not None:
                conditions.append(SecurityLog.log_source == log_source)
            if processing_status is not None:
                conditions.append(SecurityLog.processing_status == processing_status)

        if security_log_id is not None:
            conditions.append(ParsedLog.security_log_id == security_log_id)
        if event_type:
            conditions.append(ParsedLog.event_type == event_type)
        if severity is not None:
            conditions.append(ParsedLog.severity == severity)
        if source_ip:
            conditions.append(ParsedLog.source_ip == source_ip)
        if destination_ip:
            conditions.append(ParsedLog.destination_ip == destination_ip)
        if hostname:
            conditions.append(ParsedLog.hostname.ilike(f"%{hostname}%"))
        if username:
            conditions.append(ParsedLog.username.ilike(f"%{username}%"))
        if event_id:
            conditions.append(ParsedLog.event_id == event_id)
        if protocol:
            conditions.append(ParsedLog.protocol == protocol)
        if action:
            conditions.append(ParsedLog.action == action)
        if date_from is not None:
            conditions.append(ParsedLog.timestamp >= date_from)
        if date_to is not None:
            conditions.append(ParsedLog.timestamp <= date_to)
        if search:
            like_pattern = f"%{search}%"
            conditions.append(
                or_(ParsedLog.message.ilike(like_pattern), ParsedLog.raw_log.ilike(like_pattern))
            )

        base_stmt = base_stmt.where(*conditions)
        count_stmt = count_stmt.where(*conditions)

        sort_column = self._SORTABLE_FIELDS.get(sort_by, ParsedLog.timestamp)
        order_clause = sort_column.desc() if sort_order == "desc" else sort_column.asc()

        page_stmt = base_stmt.order_by(order_clause).offset(skip).limit(limit)

        items = self.db.execute(page_stmt).scalars().all()
        total = self.db.execute(count_stmt).scalar_one()
        return items, total

