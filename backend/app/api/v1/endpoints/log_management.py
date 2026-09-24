"""
Log management endpoints — bulk operations and statistics (Part 7).

Registered under the same "/logs" prefix as Parts 5/6's endpoints. Literal
sub-paths here ("/bulk-delete", "/bulk-reparse", "/bulk-status",
"/statistics") never collide with the "/{log_id}" pattern in logs.py /
parsing.py because log_id is UUID-typed — Starlette only matches that route
when the path segment successfully converts to a UUID, regardless of
registration order.
"""

from fastapi import APIRouter, Depends

from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_log_management_service
from app.models.user import User
from app.schemas.base import ResponseSchema
from app.schemas.log_management import (
    BulkLogIdsRequest,
    BulkOperationSummary,
    BulkReparseRequest,
    BulkStatusItem,
    LogStatistics,
)
from app.services.log_management_service import LogManagementService

router = APIRouter(prefix="/logs", tags=["Log Management"])


@router.post(
    "/bulk-delete",
    response_model=ResponseSchema[BulkOperationSummary],
    summary="Delete multiple uploaded log files in one request",
)
def bulk_delete_logs(
    request: BulkLogIdsRequest,
    current_user: User = Depends(get_current_active_user),
    log_management_service: LogManagementService = Depends(get_log_management_service),
) -> ResponseSchema:
    """
    Partial-success semantics: each id is independently authorized and
    deleted (or reported as failed) — one inaccessible or already-processed
    log does not block deletion of the others. See BulkOperationSummary's
    docstring for the full rationale.
    """
    summary = log_management_service.bulk_delete(request.log_ids, current_user)
    return ResponseSchema(
        success=True,
        message=f"{summary.succeeded}/{summary.total} logs deleted.",
        data=summary,
    )


@router.post(
    "/bulk-reparse",
    response_model=ResponseSchema[BulkOperationSummary],
    summary="Re-parse multiple uploaded log files in one request (reuses Part 6's ParserService)",
)
def bulk_reparse_logs(
    request: BulkReparseRequest,
    current_user: User = Depends(get_current_active_user),
    log_management_service: LogManagementService = Depends(get_log_management_service),
) -> ResponseSchema:
    summary = log_management_service.bulk_reparse(request.log_ids, current_user, force=request.force)
    return ResponseSchema(
        success=True,
        message=f"{summary.succeeded}/{summary.total} logs re-parsed.",
        data=summary,
    )


@router.post(
    "/bulk-status",
    response_model=ResponseSchema[list[BulkStatusItem]],
    summary="Look up processing status and parsed-record counts for multiple logs in one request",
)
def bulk_status_logs(
    request: BulkLogIdsRequest,
    current_user: User = Depends(get_current_active_user),
    log_management_service: LogManagementService = Depends(get_log_management_service),
) -> ResponseSchema:
    """Single database query for the whole batch — see SecurityLogRepository.get_bulk_status."""
    items = log_management_service.bulk_status(request.log_ids, current_user)
    return ResponseSchema(success=True, data=items)


@router.get(
    "/statistics",
    response_model=ResponseSchema[LogStatistics],
    summary="Aggregate statistics over uploaded/parsed logs (scoped to your own uploads unless you hold LOG_READ_ANY)",
)
def get_log_statistics(
    current_user: User = Depends(get_current_active_user),
    log_management_service: LogManagementService = Depends(get_log_management_service),
) -> ResponseSchema:
    stats = log_management_service.get_statistics(current_user)
    return ResponseSchema(success=True, data=stats)
