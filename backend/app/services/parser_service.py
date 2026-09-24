"""
Parser service — orchestrates the parse-a-file workflow for the Log Parser
Engine (Part 6): read stored bytes -> pick a parser via ParserFactory ->
normalize -> batch-insert ParsedLog rows -> update SecurityLog status.

Async-readiness note (per Part 6 spec: "prepare the architecture for future
asynchronous/background processing without implementing it now"): every
method here takes plain models/IDs and returns plain data — never a
Request/Response object — so `parse_upload` could be handed to a background
task queue (Celery, RQ, FastAPI BackgroundTasks) later by simply changing
who calls it, with no change to this class itself. It runs synchronously
for now, as specified.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime
from typing import Sequence

from app.core.exceptions import ConflictError, ForbiddenError, ValidationFailedError
from app.logs.parsers import ParserFactory, UnsupportedFormatError
from app.models.enums import LogSource, ProcessingStatus, RiskLevel
from app.models.parsed_log import ParsedLog
from app.models.security_log import SecurityLog
from app.models.user import User
from app.repositories.parsed_log_repository import ParsedLogRepository
from app.repositories.security_log_repository import SecurityLogRepository
from app.schemas.parsed_log import ParseResultSummary
from app.security.permissions import Permission, role_has_permission
from app.utils.storage import LocalFileStorage

logger = logging.getLogger(__name__)

_BULK_INSERT_BATCH_SIZE = 500


class ParserService:
    def __init__(
        self,
        security_log_repository: SecurityLogRepository,
        parsed_log_repository: ParsedLogRepository,
        storage: LocalFileStorage,
    ):
        self.security_log_repository = security_log_repository
        self.parsed_log_repository = parsed_log_repository
        self.storage = storage

    # --- Authorization (self-contained, mirrors UploadService.delete_upload's pattern) ---

    def _authorize(self, security_log: SecurityLog, requesting_user: User) -> None:
        is_owner = security_log.uploaded_by_id == requesting_user.id
        if is_owner:
            if not role_has_permission(requesting_user.role, Permission.LOG_PARSE):
                raise ForbiddenError("You do not have permission to parse logs.")
            return
        if not role_has_permission(requesting_user.role, Permission.LOG_PARSE_ANY):
            raise ForbiddenError("You do not have permission to parse other users' logs.")

    # --- Parse / reparse ---

    def parse_upload(
        self, security_log: SecurityLog, requesting_user: User, *, force_reparse: bool = False
    ) -> ParseResultSummary:
        self._authorize(security_log, requesting_user)

        if security_log.processing_status == ProcessingStatus.PROCESSING:
            raise ConflictError("This log is already being processed.")
        if security_log.processing_status == ProcessingStatus.COMPLETED and not force_reparse:
            raise ConflictError(
                "This log has already been parsed. Use the reparse endpoint to force re-processing."
            )

        security_log.processing_status = ProcessingStatus.PROCESSING
        self.security_log_repository.update(security_log)

        try:
            if force_reparse:
                self.parsed_log_repository.delete_by_security_log_id(security_log.id)

            content = self.storage.read(security_log.storage_path)
            parser = ParserFactory.get_parser(security_log.file_type)

            entries_created = self._parse_and_persist(parser, content, security_log)
            errors = list(parser.errors)

            # A file that produced zero entries AND had errors covering
            # every record is a hard failure; partial success (some
            # entries, some errors) is still COMPLETED with errors reported.
            final_status = (
                ProcessingStatus.FAILED
                if entries_created == 0 and errors
                else ProcessingStatus.COMPLETED
            )
            security_log.processing_status = final_status
            self.security_log_repository.update(security_log)

            logger.info(
                "Parsed security_log=%s: %d entries created, %d errors, status=%s",
                security_log.id,
                entries_created,
                len(errors),
                final_status.value,
            )

            return ParseResultSummary.build(
                security_log_id=security_log.id,
                processing_status=final_status,
                entries_created=entries_created,
                errors=errors,
            )

        except UnsupportedFormatError as exc:
            security_log.processing_status = ProcessingStatus.FAILED
            self.security_log_repository.update(security_log)
            raise ValidationFailedError(str(exc)) from exc
        except Exception:
            security_log.processing_status = ProcessingStatus.FAILED
            self.security_log_repository.update(security_log)
            logger.exception("Unhandled error parsing security_log=%s", security_log.id)
            raise

    def _parse_and_persist(self, parser, content: bytes, security_log: SecurityLog) -> int:
        """Consume the parser's generator in batches, never holding the full result set in memory."""
        entries_created = 0
        batch: list[ParsedLog] = []

        for entry in parser.parse(content):
            batch.append(
                ParsedLog(
                    security_log_id=security_log.id,
                    # Fall back to the file's own upload_time when a record's
                    # timestamp couldn't be parsed — ParsedLog.timestamp is
                    # NOT NULL (Part 3), and "around when the file was
                    # uploaded" is a reasonable, documented proxy rather than
                    # loosening that constraint.
                    timestamp=entry.timestamp or security_log.upload_time,
                    source_ip=entry.source_ip,
                    destination_ip=entry.destination_ip,
                    source_port=entry.source_port,
                    destination_port=entry.destination_port,
                    username=entry.username,
                    hostname=entry.hostname,
                    event_id=entry.event_id,
                    event_type=entry.event_type,
                    severity=entry.severity,
                    protocol=entry.protocol,
                    action=entry.action,
                    message=entry.message,
                    raw_log=entry.raw_log,
                )
            )
            entries_created += 1
            if len(batch) >= _BULK_INSERT_BATCH_SIZE:
                self.parsed_log_repository.bulk_create(batch)
                batch = []

        if batch:
            self.parsed_log_repository.bulk_create(batch)

        return entries_created

    # --- Status / listing ---

    def get_parsing_status(self, security_log: SecurityLog) -> tuple[ProcessingStatus, int]:
        count = self.parsed_log_repository.count_by_security_log_id(security_log.id)
        return security_log.processing_status, count

    def list_parsed_records_for_log(
        self,
        security_log: SecurityLog,
        *,
        skip: int = 0,
        limit: int = 20,
        sort_by: str = "timestamp",
        sort_order: str = "desc",
    ) -> tuple[Sequence[ParsedLog], int]:
        return self.parsed_log_repository.search(
            security_log_id=security_log.id,
            skip=skip,
            limit=limit,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    def list_all_parsed_logs(
        self,
        *,
        requesting_user: User,
        security_log_id: uuid.UUID | None = None,
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
        """Users without LOG_READ_ANY only see parsed records from their own uploads."""
        uploaded_by_id = None
        if not role_has_permission(requesting_user.role, Permission.LOG_READ_ANY):
            uploaded_by_id = requesting_user.id

        return self.parsed_log_repository.search(
            security_log_id=security_log_id,
            uploaded_by_id=uploaded_by_id,
            event_type=event_type,
            severity=severity,
            source_ip=source_ip,
            destination_ip=destination_ip,
            hostname=hostname,
            username=username,
            event_id=event_id,
            protocol=protocol,
            action=action,
            log_source=log_source,
            processing_status=processing_status,
            date_from=date_from,
            date_to=date_to,
            search=search,
            skip=skip,
            limit=limit,
            sort_by=sort_by,
            sort_order=sort_order,
        )
