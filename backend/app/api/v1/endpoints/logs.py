"""Log upload endpoints — upload, list, retrieve, delete. Storage/validation only — no parsing (Part 6)."""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, File, Form, Query, UploadFile, status

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.dependencies.auth import get_current_active_user
from app.dependencies.rbac import require_permissions
from app.dependencies.services import get_audit_service, get_upload_service
from app.models.enums import LogSource, ProcessingStatus
from app.models.user import User
from app.schemas.base import PaginatedResponseSchema, ResponseSchema
from app.schemas.security_log import SecurityLogOut
from app.security.permissions import Permission
from app.services.audit_service import AuditService
from app.services.upload_service import UploadService

router = APIRouter(prefix="/logs", tags=["Log Upload"])


@router.post(
    "/upload",
    response_model=ResponseSchema[SecurityLogOut],
    status_code=status.HTTP_201_CREATED,
    summary="Upload a security log file (multipart/form-data)",
    dependencies=[Depends(require_permissions(Permission.LOG_UPLOAD))],
)
async def upload_log(
    file: UploadFile = File(..., description="CSV, JSON, .log, or .txt security log file"),
    log_source: LogSource = Form(..., description="Origin system category of this log file"),
    current_user: User = Depends(get_current_active_user),
    upload_service: UploadService = Depends(get_upload_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> ResponseSchema:
    security_log = await upload_service.upload(file, current_user, log_source)
    audit_service.log(
        action="LOG_UPLOAD",
        user=current_user,
        object_type="SECURITY_LOG",
        object_id=str(security_log.id),
        details={
            "filename": security_log.original_filename,
            "source": log_source.value,
            "size": security_log.file_size,
        },
    )
    return ResponseSchema(success=True, message="File uploaded successfully.", data=security_log)


@router.get(
    "",
    response_model=PaginatedResponseSchema[SecurityLogOut],
    summary="List/search uploaded log files (paginated, filterable, sortable)",
)
def list_logs(
    search: str | None = Query(default=None, description="Matches filename or original filename"),
    log_source: LogSource | None = Query(default=None),
    processing_status: ProcessingStatus | None = Query(default=None),
    file_type: str | None = Query(default=None, description="e.g. csv, json, log, txt"),
    uploaded_by_username: str | None = Query(
        default=None, description="Matches the uploading user's username (LOG_READ_ANY only sees others')"
    ),
    upload_date_from: datetime | None = Query(default=None, description="Upload time lower bound (inclusive)"),
    upload_date_to: datetime | None = Query(default=None, description="Upload time upper bound (inclusive)"),
    file_size_min: int | None = Query(default=None, ge=0, description="Minimum file size in bytes"),
    file_size_max: int | None = Query(default=None, ge=0, description="Maximum file size in bytes"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    sort_by: str = Query(
        default="upload_time",
        pattern="^(upload_time|created_at|original_filename|file_size|event_count)$",
    ),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    current_user: User = Depends(get_current_active_user),
    upload_service: UploadService = Depends(get_upload_service),
) -> PaginatedResponseSchema:
    """Users without the LOG_READ_ANY permission only see their own uploads."""
    items, total = upload_service.list_uploads(
        requesting_user=current_user,
        log_source=log_source,
        processing_status=processing_status,
        file_type=file_type,
        uploaded_by_username=uploaded_by_username,
        upload_date_from=upload_date_from,
        upload_date_to=upload_date_to,
        file_size_min=file_size_min,
        file_size_max=file_size_max,
        search=search,
        skip=skip,
        limit=limit,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return PaginatedResponseSchema(data=list(items), total=total, skip=skip, limit=limit)


@router.get(
    "/{log_id}",
    response_model=ResponseSchema[SecurityLogOut],
    summary="Get details of a single uploaded log file",
)
def get_log(
    log_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    upload_service: UploadService = Depends(get_upload_service),
) -> ResponseSchema:
    security_log = upload_service.get_upload_or_404(log_id, current_user)
    return ResponseSchema(success=True, data=security_log)


@router.delete(
    "/{log_id}",
    response_model=ResponseSchema,
    summary="Delete an uploaded log file (only if not yet processed)",
)
def delete_log(
    log_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    upload_service: UploadService = Depends(get_upload_service),
) -> ResponseSchema:
    security_log = upload_service.get_upload_or_404(log_id, current_user)
    upload_service.delete_upload(security_log, current_user)
    return ResponseSchema(success=True, message="Upload deleted successfully.")
