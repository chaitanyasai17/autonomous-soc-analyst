"""User request/response schemas (API boundary DTOs — see app/models/user.py for the ORM entity)."""

from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import EmailStr, Field, field_validator

from app.models.enums import UserRole
from app.schemas.base import BaseSchema
from app.utils.validators import is_strong_password


class UserBase(BaseSchema):
    username: str = Field(min_length=3, max_length=50)
    email: EmailStr
    first_name: str = Field(min_length=1, max_length=100)
    last_name: str = Field(min_length=1, max_length=100)


class UserCreate(UserBase):
    """Registration payload. Role is intentionally NOT accepted here — new
    accounts always start as ANALYST; role elevation is an explicit admin
    action via UserAdminUpdate, preventing privilege self-escalation at
    signup."""

    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        if not is_strong_password(value):
            raise ValueError(
                "Password must be at least 8 characters and include both a letter and a digit."
            )
        return value


class UserProfileUpdate(BaseSchema):
    """Self-service profile update — no role/is_active fields (see UserAdminUpdate)."""

    first_name: str | None = Field(default=None, min_length=1, max_length=100)
    last_name: str | None = Field(default=None, min_length=1, max_length=100)
    email: EmailStr | None = None


class UserAdminUpdate(BaseSchema):
    """Admin-only update — role and activation state."""

    role: UserRole | None = None
    is_active: bool | None = None


class UserOut(UserBase):
    """Public user representation. Never includes password_hash."""

    id: uuid.UUID
    role: UserRole
    is_active: bool
    created_at: datetime
    updated_at: datetime


class PasswordChangeRequest(BaseSchema):
    current_password: str
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        if not is_strong_password(value):
            raise ValueError(
                "Password must be at least 8 characters and include both a letter and a digit."
            )
        return value
