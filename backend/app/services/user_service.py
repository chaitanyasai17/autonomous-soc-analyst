"""User service — business logic for profile management and admin user operations."""

from __future__ import annotations

import uuid
from typing import Sequence

from app.core.exceptions import ConflictError, ValidationFailedError
from app.models.enums import UserRole
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.user import UserAdminUpdate, UserProfileUpdate
from app.services.base import BaseService


class UserService(BaseService[User]):
    """Application-layer service for user profile and administration use cases."""

    def __init__(self, repository: UserRepository):
        super().__init__(repository=repository)
        self.repository: UserRepository = repository  # narrow type for IDE/mypy

    def get_user_or_404(self, user_id: uuid.UUID) -> User:
        return self.get_or_404(user_id)

    def list_users(
        self,
        *,
        search: str | None = None,
        role: UserRole | None = None,
        is_active: bool | None = None,
        skip: int = 0,
        limit: int = 20,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> tuple[Sequence[User], int]:
        return self.repository.search(
            search=search,
            role=role,
            is_active=is_active,
            skip=skip,
            limit=limit,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    def update_profile(self, user: User, data: UserProfileUpdate) -> User:
        """Self-service update — caller must already own `user` (enforced by the route)."""
        if data.email is not None and data.email != user.email:
            if self.repository.exists_by_email(data.email):
                raise ConflictError("Email is already in use.")
            user.email = data.email
        if data.first_name is not None:
            user.first_name = data.first_name
        if data.last_name is not None:
            user.last_name = data.last_name
        return self.repository.update(user)

    def admin_update_user(self, user: User, data: UserAdminUpdate) -> User:
        """Admin-only update — role and activation state (see UserAdminUpdate)."""
        if data.role is not None:
            user.role = data.role
        if data.is_active is not None:
            user.is_active = data.is_active
        return self.repository.update(user)

    def activate(self, user: User) -> User:
        user.is_active = True
        return self.repository.update(user)

    def deactivate(self, user: User) -> User:
        user.is_active = False
        return self.repository.update(user)

    def soft_delete(self, user: User) -> User:
        return self.repository.soft_delete(user)

    def restore(self, user: User, *, requested_role_active: bool = True) -> User:
        if user.deleted_at is None:
            raise ValidationFailedError("User is not deleted.")
        restored = self.repository.restore(user)
        if requested_role_active:
            restored = self.activate(restored)
        return restored
