"""
Notification endpoints — in-app notifications, unread count, and status updates.
"""

import uuid

from fastapi import APIRouter, Depends, Query

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_notification_service
from app.models.user import User
from app.schemas.base import PaginatedResponseSchema, ResponseSchema
from app.schemas.notification import NotificationOut, UnreadCountOut
from app.services.notification_service import NotificationService

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get(
    "/unread-count",
    response_model=ResponseSchema[UnreadCountOut],
    summary="Get count of unread notifications for current user",
)
def get_unread_count(
    current_user: User = Depends(get_current_active_user),
    notification_service: NotificationService = Depends(get_notification_service),
) -> ResponseSchema:
    data = notification_service.get_unread_count(current_user.id)
    return ResponseSchema(success=True, data=data)


@router.get(
    "",
    response_model=PaginatedResponseSchema[NotificationOut],
    summary="List notifications for current user",
)
def list_notifications(
    unread_only: bool = Query(default=False, description="Filter to only unread notifications"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    current_user: User = Depends(get_current_active_user),
    notification_service: NotificationService = Depends(get_notification_service),
) -> PaginatedResponseSchema:
    items, total = notification_service.list_user_notifications(
        recipient_id=current_user.id, unread_only=unread_only, skip=skip, limit=limit
    )
    return PaginatedResponseSchema(
        success=True,
        data=items,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.patch(
    "/{notification_id}/read",
    response_model=ResponseSchema[NotificationOut],
    summary="Mark a single notification as read",
)
def mark_read(
    notification_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    notification_service: NotificationService = Depends(get_notification_service),
) -> ResponseSchema:
    res = notification_service.mark_read(notification_id, current_user.id)
    return ResponseSchema(success=True, message="Marked as read.", data=res)


@router.post(
    "/read-all",
    response_model=ResponseSchema,
    summary="Mark all notifications as read for current user",
)
def mark_all_read(
    current_user: User = Depends(get_current_active_user),
    notification_service: NotificationService = Depends(get_notification_service),
) -> ResponseSchema:
    count = notification_service.mark_all_read(current_user.id)
    return ResponseSchema(success=True, message=f"Marked {count} notification(s) as read.")
