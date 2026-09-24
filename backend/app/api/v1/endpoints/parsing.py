"""
Log parsing endpoints — trigger parsing/reparsing, check status, and browse
parsed records. Normalization only — no Sigma/MITRE/AI/risk logic (Part 7+).

Note: parse/reparse are declared as regular `def` (not `async def`) so
FastAPI runs them in its external threadpool — a slow parse of a large file
never blocks the event loop for other concurrent requests.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_parser_service, get_upload_service
from app.models.enums import LogSource, ProcessingStatus, RiskLevel
from app.models.user import User
from app.schemas.base import PaginatedResponseSchema, ResponseSchema
from app.schemas.parsed_log import ParseResultSummary, ParsedLogOut, ParsingStatusOut
from app.services.parser_service import ParserService
from app.services.upload_service import UploadService

router = APIRouter(prefix="/logs", tags=["Log Parsing"])
parsed_logs_router = APIRouter(prefix="/parsed-logs", tags=["Log Parsing"])


@router.post(
    "/{log_id}/parse",
    response_model=ResponseSchema[ParseResultSummary],
    summary="Parse an uploaded log file into normalized records",
)
def parse_log(
    log_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    upload_service: UploadService = Depends(get_upload_service),
    parser_service: ParserService = Depends(get_parser_service),
) -> ResponseSchema:
    security_log = upload_service.get_upload_or_404(log_id, current_user)
    summary = parser_service.parse_upload(security_log, current_user, force_reparse=False)
    return ResponseSchema(success=True, message="Parsing completed.", data=summary)


@router.post(
    "/{log_id}/reparse",
    response_model=ResponseSchema[ParseResultSummary],
    summary="Re-parse an uploaded log file, discarding any previously parsed records for it",
)
def reparse_log(
    log_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    upload_service: UploadService = Depends(get_upload_service),
    parser_service: ParserService = Depends(get_parser_service),
) -> ResponseSchema:
    security_log = upload_service.get_upload_or_404(log_id, current_user)
    summary = parser_service.parse_upload(security_log, current_user, force_reparse=True)
    return ResponseSchema(success=True, message="Re-parsing completed.", data=summary)


@router.get(
    "/{log_id}/parsing-status",
    response_model=ResponseSchema[ParsingStatusOut],
    summary="Check the parsing status of an uploaded log file",
)
def get_parsing_status(
    log_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    upload_service: UploadService = Depends(get_upload_service),
    parser_service: ParserService = Depends(get_parser_service),
) -> ResponseSchema:
    security_log = upload_service.get_upload_or_404(log_id, current_user)
    status_value, count = parser_service.get_parsing_status(security_log)
    return ResponseSchema(
        success=True,
        data=ParsingStatusOut(
            security_log_id=security_log.id,
            processing_status=status_value,
            parsed_record_count=count,
        ),
    )


@router.get(
    "/{log_id}/parsed-records",
    response_model=PaginatedResponseSchema[ParsedLogOut],
    summary="List normalized records parsed from one uploaded log file",
)
def list_parsed_records(
    log_id: uuid.UUID,
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    sort_by: str = Query(default="timestamp", pattern="^(timestamp|created_at|severity|event_type)$"),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    current_user: User = Depends(get_current_active_user),
    upload_service: UploadService = Depends(get_upload_service),
    parser_service: ParserService = Depends(get_parser_service),
) -> PaginatedResponseSchema:
    security_log = upload_service.get_upload_or_404(log_id, current_user)
    items, total = parser_service.list_parsed_records_for_log(
        security_log, skip=skip, limit=limit, sort_by=sort_by, sort_order=sort_order
    )
    return PaginatedResponseSchema(data=list(items), total=total, skip=skip, limit=limit)


@parsed_logs_router.get(
    "",
    response_model=PaginatedResponseSchema[ParsedLogOut],
    summary="Search/list normalized log records across all uploads (paginated, filterable, sortable)",
)
def list_all_parsed_logs(
    security_log_id: uuid.UUID | None = Query(default=None),
    event_type: str | None = Query(default=None),
    severity: RiskLevel | None = Query(default=None),
    source_ip: str | None = Query(default=None),
    destination_ip: str | None = Query(default=None),
    hostname: str | None = Query(default=None),
    username: str | None = Query(default=None),
    event_id: str | None = Query(default=None),
    protocol: str | None = Query(default=None),
    action: str | None = Query(default=None),
    log_source: LogSource | None = Query(default=None, description="Origin category of the parent uploaded file"),
    processing_status: ProcessingStatus | None = Query(
        default=None, description="Processing status of the parent uploaded file"
    ),
    date_from: datetime | None = Query(default=None, description="Event timestamp lower bound (inclusive)"),
    date_to: datetime | None = Query(default=None, description="Event timestamp upper bound (inclusive)"),
    search: str | None = Query(default=None, description="Matches message or raw_log"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    sort_by: str = Query(default="timestamp", pattern="^(timestamp|created_at|severity|event_type)$"),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    current_user: User = Depends(get_current_active_user),
    parser_service: ParserService = Depends(get_parser_service),
) -> PaginatedResponseSchema:
    """Users without LOG_READ_ANY only see parsed records from their own uploads."""
    items, total = parser_service.list_all_parsed_logs(
        requesting_user=current_user,
        security_log_id=security_log_id,
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
    return PaginatedResponseSchema(data=list(items), total=total, skip=skip, limit=limit)
