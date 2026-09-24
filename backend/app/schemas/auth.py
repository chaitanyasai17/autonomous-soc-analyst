"""Authentication request/response schemas."""

from __future__ import annotations

from pydantic import EmailStr, Field, field_validator

from app.schemas.base import BaseSchema
from app.utils.validators import is_strong_password


class TokenResponse(BaseSchema):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds until access_token expiry


class RefreshTokenRequest(BaseSchema):
    refresh_token: str


class LogoutRequest(BaseSchema):
    refresh_token: str


class ForgotPasswordRequest(BaseSchema):
    email: EmailStr


class ResetPasswordRequest(BaseSchema):
    token: str
    new_password: str = Field(min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, value: str) -> str:
        if not is_strong_password(value):
            raise ValueError(
                "Password must be at least 8 characters and include both a letter and a digit."
            )
        return value
