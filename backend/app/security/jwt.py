"""
JWT helper utilities.

Provides pure encode/decode functions only. Login/register/refresh
ENDPOINTS, current-user resolution, and RBAC checks are out of scope for
Part 2 and will be implemented in Part 4 — Authentication & User Management,
on top of these helpers.
"""

from datetime import datetime, timedelta, timezone
from typing import Any
from uuid import UUID, uuid4

from jose import JWTError, jwt

from app.config import get_settings
from app.security.constants import (
    CLAIM_EXPIRES_AT,
    CLAIM_ISSUED_AT,
    CLAIM_JTI,
    CLAIM_SUBJECT,
    CLAIM_TOKEN_TYPE,
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_PASSWORD_RESET,
    TOKEN_TYPE_REFRESH,
)


class TokenError(Exception):
    """Raised when a token is invalid, malformed, or expired."""


def _create_token(
    subject: str, token_type: str, expires_delta: timedelta, include_jti: bool = False
) -> str:
    settings = get_settings()
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        CLAIM_SUBJECT: subject,
        CLAIM_TOKEN_TYPE: token_type,
        CLAIM_ISSUED_AT: now,
        CLAIM_EXPIRES_AT: now + expires_delta,
    }
    if include_jti:
        payload[CLAIM_JTI] = str(uuid4())
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def create_access_token(subject: str) -> str:
    """Create a short-lived access token for the given subject (e.g., user id)."""
    settings = get_settings()
    return _create_token(
        subject,
        TOKEN_TYPE_ACCESS,
        timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES),
    )


def create_refresh_token(subject: str) -> str:
    """
    Create a long-lived refresh token for the given subject.

    Includes a `jti` (JWT ID) claim so an individual refresh token can be
    revoked (logout, rotation) without invalidating every token for the
    user — see app/security/token_blacklist.py.
    """
    settings = get_settings()
    return _create_token(
        subject,
        TOKEN_TYPE_REFRESH,
        timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS),
        include_jti=True,
    )


def create_password_reset_token(subject: str) -> str:
    """Create a short-lived, single-purpose password reset token."""
    settings = get_settings()
    return _create_token(
        subject,
        TOKEN_TYPE_PASSWORD_RESET,
        timedelta(minutes=settings.PASSWORD_RESET_TOKEN_EXPIRE_MINUTES),
    )


def decode_token(token: str) -> dict[str, Any]:
    """
    Decode and verify a JWT.

    Raises TokenError if the token is invalid, malformed, or expired.
    """
    settings = get_settings()
    try:
        return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    except JWTError as exc:
        raise TokenError("Invalid or expired token.") from exc


def parse_subject_uuid(value: str | None) -> UUID | None:
    """
    Safely parse a JWT `sub` claim (always a string) into a UUID.

    Used wherever a decoded token's subject needs to become a repository
    lookup key — the User primary key is a UUID column, and passing a raw
    string through to the DB layer risks driver-dependent behavior.
    Returns None (rather than raising) on any malformed input so callers can
    uniformly treat it as "no such user" via their own not-found handling.
    """
    if not value:
        return None
    try:
        return UUID(value)
    except (ValueError, AttributeError, TypeError):
        return None
