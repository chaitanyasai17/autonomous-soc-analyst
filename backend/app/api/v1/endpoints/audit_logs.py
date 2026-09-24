"""
Audit Log endpoints — Browse and inspect immutable SOC audit records.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_audit_service
from app.models.user import User
from app.schemas.audit_log import AuditLogOut
from app.schemas.base import PaginatedResponseSchema, ResponseSchema
from app.services.audit_service import AuditService

router = APIRouter(prefix="/audit-logs", tags=["Audit Trail"])


@router.get(
    "",
    response_model=PaginatedResponseSchema[AuditLogOut],
    summary="Search and paginate immutable operational audit trail",
)
def list_audit_logs(
    action: str | None = Query(default=None),
    user_id: uuid.UUID | None = Query(default=None),
    username: str | None = Query(default=None),
    object_type: str | None = Query(default=None),
    object_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    current_user: User = Depends(get_current_active_user),
    audit_service: AuditService = Depends(get_audit_service),
) -> PaginatedResponseSchema:
    items, total = audit_service.search(
        action=action,
        user_id=user_id,
        username=username,
        object_type=object_type,
        object_id=object_id,
        status=status,
        date_from=date_from,
        date_to=date_to,
        skip=skip,
        limit=limit,
    )
    return PaginatedResponseSchema(data=list(items), total=total, skip=skip, limit=limit)


@router.get(
    "/{log_id}",
    response_model=ResponseSchema[AuditLogOut],
    summary="Get a single audit log entry by ID",
)
def get_audit_log(
    log_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    audit_service: AuditService = Depends(get_audit_service),
) -> ResponseSchema:
    item = audit_service.get_by_id(log_id)
    return ResponseSchema(success=True, data=item)


# Alias router under /audit for direct access
audit_alias_router = APIRouter(prefix="/audit", tags=["Audit Trail"])

@audit_alias_router.get(
    "",
    response_model=PaginatedResponseSchema[AuditLogOut],
    summary="Search and paginate immutable operational audit trail (alias)",
)
def list_audit_logs_alias(
    action: str | None = Query(default=None),
    user_id: uuid.UUID | None = Query(default=None),
    username: str | None = Query(default=None),
    object_type: str | None = Query(default=None),
    object_id: str | None = Query(default=None),
    status: str | None = Query(default=None),
    date_from: datetime | None = Query(default=None),
    date_to: datetime | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    current_user: User = Depends(get_current_active_user),
    audit_service: AuditService = Depends(get_audit_service),
) -> PaginatedResponseSchema:
    return list_audit_logs(
        action=action,
        user_id=user_id,
        username=username,
        object_type=object_type,
        object_id=object_id,
        status=status,
        date_from=date_from,
        date_to=date_to,
        skip=skip,
        limit=limit,
        current_user=current_user,
        audit_service=audit_service,
    )

