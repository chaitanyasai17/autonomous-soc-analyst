"""User repository — data access only, no business rules (see services/user_service.py)."""

from __future__ import annotations

import uuid
from typing import Sequence

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.enums import UserRole
from app.models.user import User
from app.repositories.base import BaseRepository


class UserRepository(BaseRepository[User]):
    """Repository encapsulating all direct queries against the users table."""

    def __init__(self, db: Session):
        super().__init__(model=User, db=db)

    # --- Lookups ---

    def get_by_id_including_deleted(self, user_id: uuid.UUID) -> User | None:
        """Fetch a user by id regardless of soft-delete state (admin restore flow)."""
        return self.db.get(User, user_id)

    def get_by_username(self, username: str) -> User | None:
        stmt = select(User).where(User.username == username, User.deleted_at.is_(None))
        return self.db.execute(stmt).scalar_one_or_none()

    def get_by_email(self, email: str) -> User | None:
        stmt = select(User).where(User.email == email, User.deleted_at.is_(None))
        return self.db.execute(stmt).scalar_one_or_none()

    def get_by_username_or_email(self, identifier: str) -> User | None:
        stmt = select(User).where(
            or_(User.username == identifier, User.email == identifier),
            User.deleted_at.is_(None),
        )
        return self.db.execute(stmt).scalar_one_or_none()

    def exists_by_username(self, username: str) -> bool:
        return self.get_by_username(username) is not None

    def exists_by_email(self, email: str) -> bool:
        return self.get_by_email(email) is not None

    # --- Search / list with pagination, filtering, sorting ---

    _SORTABLE_FIELDS = {
        "username": User.username,
        "email": User.email,
        "created_at": User.created_at,
        "role": User.role,
    }

    def search(
        self,
        *,
        search: str | None = None,
        role: UserRole | None = None,
        is_active: bool | None = None,
        include_deleted: bool = False,
        skip: int = 0,
        limit: int = 20,
        sort_by: str = "created_at",
        sort_order: str = "desc",
    ) -> tuple[Sequence[User], int]:
        """Return (page_of_users, total_matching_count) for the given filters."""
        conditions = []
        if not include_deleted:
            conditions.append(User.deleted_at.is_(None))
        if search:
            like_pattern = f"%{search}%"
            conditions.append(
                or_(
                    User.username.ilike(like_pattern),
                    User.email.ilike(like_pattern),
                    User.first_name.ilike(like_pattern),
                    User.last_name.ilike(like_pattern),
                )
            )
        if role is not None:
            conditions.append(User.role == role)
        if is_active is not None:
            conditions.append(User.is_active == is_active)

        base_stmt = select(User).where(*conditions)
        count_stmt = select(func.count()).select_from(User).where(*conditions)

        sort_column = self._SORTABLE_FIELDS.get(sort_by, User.created_at)
        order_clause = sort_column.desc() if sort_order == "desc" else sort_column.asc()

        page_stmt = base_stmt.order_by(order_clause).offset(skip).limit(limit)

        items = self.db.execute(page_stmt).scalars().all()
        total = self.db.execute(count_stmt).scalar_one()
        return items, total

    # --- Soft delete lifecycle (User has SoftDeleteMixin) ---

    def soft_delete(self, user: User) -> User:
        from app.utils.datetime_utils import utc_now

        user.deleted_at = utc_now()
        user.is_active = False
        return self.update(user)

    def restore(self, user: User) -> User:
        user.deleted_at = None
        return self.update(user)
