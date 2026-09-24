"""User management endpoints — CRUD, search/pagination/filtering/sorting, lifecycle actions."""

import uuid

from fastapi import APIRouter, Depends, Query, status

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.core.exceptions import NotFoundError
from app.dependencies.auth import get_current_active_user
from app.dependencies.rbac import require_permissions
from app.dependencies.services import get_user_service
from app.models.enums import UserRole
from app.models.user import User
from app.schemas.base import PaginatedResponseSchema, ResponseSchema
from app.schemas.user import UserAdminUpdate, UserOut, UserProfileUpdate
from app.security.permissions import Permission
from app.services.user_service import UserService

router = APIRouter(prefix="/users", tags=["Users"])


# --- Self-service routes (must be declared before /{user_id} to avoid
#     "me" being parsed as a user_id path parameter) ---


@router.get("/me", response_model=ResponseSchema[UserOut], summary="Get my own profile")
def get_my_profile(current_user: User = Depends(get_current_active_user)) -> ResponseSchema:
    return ResponseSchema(success=True, data=current_user)


@router.put("/me", response_model=ResponseSchema[UserOut], summary="Update my own profile")
def update_my_profile(
    data: UserProfileUpdate,
    current_user: User = Depends(get_current_active_user),
    user_service: UserService = Depends(get_user_service),
) -> ResponseSchema:
    updated = user_service.update_profile(current_user, data)
    return ResponseSchema(success=True, message="Profile updated.", data=updated)


# --- Administration routes ---


@router.get(
    "",
    response_model=PaginatedResponseSchema[UserOut],
    summary="List/search users (paginated, filterable, sortable)",
    dependencies=[Depends(require_permissions(Permission.USER_LIST))],
)
def list_users(
    search: str | None = Query(default=None, description="Matches username, email, or name"),
    role: UserRole | None = Query(default=None),
    is_active: bool | None = Query(default=None),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    sort_by: str = Query(default="created_at", pattern="^(username|email|created_at|role)$"),
    sort_order: str = Query(default="desc", pattern="^(asc|desc)$"),
    user_service: UserService = Depends(get_user_service),
) -> PaginatedResponseSchema:
    items, total = user_service.list_users(
        search=search,
        role=role,
        is_active=is_active,
        skip=skip,
        limit=limit,
        sort_by=sort_by,
        sort_order=sort_order,
    )
    return PaginatedResponseSchema(data=list(items), total=total, skip=skip, limit=limit)


@router.get(
    "/{user_id}",
    response_model=ResponseSchema[UserOut],
    summary="Get a user by id",
    dependencies=[Depends(require_permissions(Permission.USER_READ_ANY))],
)
def get_user(
    user_id: uuid.UUID, user_service: UserService = Depends(get_user_service)
) -> ResponseSchema:
    user = user_service.get_user_or_404(user_id)
    return ResponseSchema(success=True, data=user)


@router.put(
    "/{user_id}",
    response_model=ResponseSchema[UserOut],
    summary="Update a user's role/activation state (admin)",
    dependencies=[Depends(require_permissions(Permission.USER_UPDATE_ANY))],
)
def admin_update_user(
    user_id: uuid.UUID,
    data: UserAdminUpdate,
    user_service: UserService = Depends(get_user_service),
) -> ResponseSchema:
    user = user_service.get_user_or_404(user_id)
    updated = user_service.admin_update_user(user, data)
    return ResponseSchema(success=True, message="User updated.", data=updated)


@router.post(
    "/{user_id}/activate",
    response_model=ResponseSchema[UserOut],
    summary="Activate a user account",
    dependencies=[Depends(require_permissions(Permission.USER_DEACTIVATE))],
)
def activate_user(
    user_id: uuid.UUID, user_service: UserService = Depends(get_user_service)
) -> ResponseSchema:
    user = user_service.get_user_or_404(user_id)
    updated = user_service.activate(user)
    return ResponseSchema(success=True, message="User activated.", data=updated)


@router.post(
    "/{user_id}/deactivate",
    response_model=ResponseSchema[UserOut],
    summary="Deactivate a user account",
    dependencies=[Depends(require_permissions(Permission.USER_DEACTIVATE))],
)
def deactivate_user(
    user_id: uuid.UUID, user_service: UserService = Depends(get_user_service)
) -> ResponseSchema:
    user = user_service.get_user_or_404(user_id)
    updated = user_service.deactivate(user)
    return ResponseSchema(success=True, message="User deactivated.", data=updated)


@router.delete(
    "/{user_id}",
    response_model=ResponseSchema[UserOut],
    summary="Soft-delete a user account",
    dependencies=[Depends(require_permissions(Permission.USER_DELETE))],
)
def delete_user(
    user_id: uuid.UUID, user_service: UserService = Depends(get_user_service)
) -> ResponseSchema:
    user = user_service.get_user_or_404(user_id)
    deleted = user_service.soft_delete(user)
    return ResponseSchema(success=True, message="User deleted.", data=deleted)


@router.post(
    "/{user_id}/restore",
    response_model=ResponseSchema[UserOut],
    summary="Restore a soft-deleted user account",
    dependencies=[Depends(require_permissions(Permission.USER_RESTORE))],
)
def restore_user(
    user_id: uuid.UUID, user_service: UserService = Depends(get_user_service)
) -> ResponseSchema:
    user = user_service.repository.get_by_id_including_deleted(user_id)
    if user is None:
        raise NotFoundError(f"User with id={user_id} not found.")
    restored = user_service.restore(user)
    return ResponseSchema(success=True, message="User restored.", data=restored)
