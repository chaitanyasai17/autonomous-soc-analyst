"""
Log management service (Part 7).

Deliberately reuses UploadService and ParserService for every per-item
operation rather than reimplementing authorization/business rules —
bulk-delete calls the exact same `get_upload_or_404` + `delete_upload` path
a single-item delete would use, and bulk-reparse calls the exact same
`parse_upload` ParserService method from Part 6. This guarantees bulk and
single-item operations can never drift apart in behavior.
"""

from __future__ import annotations

import uuid
from typing import Sequence

from app.core.exceptions import ASOCException
from app.models.enums import LogSource, ProcessingStatus
from app.models.security_log import SecurityLog
from app.models.user import User
from app.repositories.security_log_repository import SecurityLogRepository
from app.schemas.log_management import BulkItemResult, BulkOperationSummary, BulkStatusItem, LogStatistics
from app.security.permissions import Permission, role_has_permission
from app.services.parser_service import ParserService
from app.services.upload_service import UploadService


class LogManagementService:
    def __init__(
        self,
        security_log_repository: SecurityLogRepository,
        upload_service: UploadService,
        parser_service: ParserService,
    ):
        self.security_log_repository = security_log_repository
        self.upload_service = upload_service
        self.parser_service = parser_service

    # --- Bulk operations ---

    def bulk_delete(self, log_ids: Sequence[uuid.UUID], requesting_user: User) -> BulkOperationSummary:
        results: list[BulkItemResult] = []
        for log_id in log_ids:
            try:
                security_log = self.upload_service.get_upload_or_404(log_id, requesting_user)
                self.upload_service.delete_upload(security_log, requesting_user)
                results.append(BulkItemResult(id=log_id, success=True, message="Deleted."))
            except ASOCException as exc:
                results.append(BulkItemResult(id=log_id, success=False, message=exc.message))
        return BulkOperationSummary.build(results)

    def bulk_reparse(
        self, log_ids: Sequence[uuid.UUID], requesting_user: User, *, force: bool = True
    ) -> BulkOperationSummary:
        results: list[BulkItemResult] = []
        for log_id in log_ids:
            try:
                security_log = self.upload_service.get_upload_or_404(log_id, requesting_user)
                summary = self.parser_service.parse_upload(
                    security_log, requesting_user, force_reparse=force
                )
                message = (
                    f"{summary.processing_status.value}: "
                    f"{summary.entries_created} entries, {summary.error_count} errors."
                )
                results.append(BulkItemResult(id=log_id, success=True, message=message))
            except ASOCException as exc:
                results.append(BulkItemResult(id=log_id, success=False, message=exc.message))
        return BulkOperationSummary.build(results)

    def bulk_status(
        self, log_ids: Sequence[uuid.UUID], requesting_user: User
    ) -> list[BulkStatusItem]:
        """Single query for the whole batch (see SecurityLogRepository.get_bulk_status) — never N+1."""
        uploaded_by_id = None
        if not role_has_permission(requesting_user.role, Permission.LOG_READ_ANY):
            uploaded_by_id = requesting_user.id

        rows = self.security_log_repository.get_bulk_status(log_ids, uploaded_by_id=uploaded_by_id)
        found_by_id = {security_log.id: (security_log, count) for security_log, count in rows}

        items: list[BulkStatusItem] = []
        for log_id in log_ids:
            match = found_by_id.get(log_id)
            if match is None:
                items.append(BulkStatusItem(id=log_id, found=False))
            else:
                security_log, count = match
                items.append(
                    BulkStatusItem(
                        id=log_id,
                        found=True,
                        processing_status=security_log.processing_status,
                        parsed_record_count=count,
                    )
                )
        return items

    # --- Statistics ---

    def get_statistics(self, requesting_user: User) -> LogStatistics:
        uploaded_by_id = None
        if not role_has_permission(requesting_user.role, Permission.LOG_READ_ANY):
            uploaded_by_id = requesting_user.id

        raw = self.security_log_repository.get_statistics(uploaded_by_id=uploaded_by_id)
        return LogStatistics(**raw)
