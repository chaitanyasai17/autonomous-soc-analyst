"""
Authentication service.

Orchestrates UserRepository + app/security helpers to implement the full
auth lifecycle. Contains no HTTP concerns — raises ASOCException subclasses,
which core/exceptions.py translates to HTTP responses.
"""

from __future__ import annotations

from functools import lru_cache

from app.config import get_settings
from app.core.exceptions import ConflictError, UnauthorizedError, ValidationFailedError
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.schemas.auth import TokenResponse
from app.schemas.user import UserCreate
from app.security.constants import CLAIM_JTI, CLAIM_SUBJECT, CLAIM_TOKEN_TYPE, TOKEN_TYPE_PASSWORD_RESET, TOKEN_TYPE_REFRESH
from app.security.hashing import hash_password, verify_password
from app.security.jwt import (
    TokenError,
    create_access_token,
    create_password_reset_token,
    create_refresh_token,
    decode_token,
    parse_subject_uuid,
)
from app.security.token_blacklist import is_revoked, revoke
from app.utils.validators import is_strong_password


@lru_cache
def _dummy_hash() -> str:
    """
    A precomputed bcrypt hash of a fixed dummy value.

    Used in authenticate() to run verify_password() even when no matching
    user exists, so "unknown username" and "wrong password" take a similar
    amount of time — reduces (does not eliminate) user-enumeration-by-timing
    risk. Cached so the bcrypt cost is only paid once per process.
    """
    return hash_password("timing-attack-mitigation-dummy-password")


class AuthService:
    """Application-layer service for authentication use cases."""

    def __init__(self, repository: UserRepository):
        self.repository = repository

    # --- Registration ---

    def register(self, data: UserCreate) -> User:
        # Deliberately generic conflict message: does not reveal whether the
        # username or the email was the one already taken, to reduce
        # account enumeration via the registration endpoint.
        if self.repository.exists_by_username(data.username) or self.repository.exists_by_email(
            data.email
        ):
            raise ConflictError("Username or email is already registered.")

        user = User(
            username=data.username,
            email=data.email,
            password_hash=hash_password(data.password),
            first_name=data.first_name,
            last_name=data.last_name,
            # New accounts always start as ANALYST — role elevation is a
            # separate, explicit admin action (see UserService.admin_update_user).
        )
        return self.repository.create(user)

    # --- Login / tokens ---

    def authenticate(self, identifier: str, password: str) -> User:
        """Verify credentials. Raises UnauthorizedError with a generic message
        on any failure (unknown user, wrong password, inactive/deleted account)
        so the client cannot distinguish these cases."""
        user = self.repository.get_by_username_or_email(identifier)
        password_hash = user.password_hash if user else _dummy_hash()
        password_valid = verify_password(password, password_hash)

        if not user or not password_valid or not user.is_active or user.deleted_at is not None:
            raise UnauthorizedError("Invalid username/email or password.")
        return user

    def _issue_tokens(self, user: User) -> TokenResponse:
        settings = get_settings()
        access_token = create_access_token(subject=str(user.id))
        refresh_token = create_refresh_token(subject=str(user.id))
        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        )

    def login(self, identifier: str, password: str) -> TokenResponse:
        user = self.authenticate(identifier, password)
        return self._issue_tokens(user)

    def refresh(self, refresh_token: str) -> TokenResponse:
        """Validate a refresh token, revoke it (rotation), and issue a new pair."""
        try:
            payload = decode_token(refresh_token)
        except TokenError as exc:
            raise UnauthorizedError("Invalid or expired refresh token.") from exc

        if payload.get(CLAIM_TOKEN_TYPE) != TOKEN_TYPE_REFRESH:
            raise UnauthorizedError("Token is not a refresh token.")

        jti = payload.get(CLAIM_JTI)
        if jti and is_revoked(jti):
            raise UnauthorizedError("Refresh token has been revoked.")

        user_id = parse_subject_uuid(payload.get(CLAIM_SUBJECT))
        user = self.repository.get_by_id(user_id) if user_id else None
        if not user or not user.is_active or user.deleted_at is not None:
            raise UnauthorizedError("User is no longer active.")

        # Rotate: revoke the presented refresh token so it cannot be reused.
        if jti:
            revoke(jti)

        return self._issue_tokens(user)

    def logout(self, refresh_token: str) -> None:
        """Revoke a refresh token. Idempotent — invalid tokens are treated as already logged out."""
        try:
            payload = decode_token(refresh_token)
        except TokenError:
            return
        jti = payload.get(CLAIM_JTI)
        if jti:
            revoke(jti)

    # --- Password management ---

    def change_password(self, user: User, current_password: str, new_password: str) -> None:
        if not verify_password(current_password, user.password_hash):
            raise UnauthorizedError("Current password is incorrect.")
        if not is_strong_password(new_password):
            raise ValidationFailedError(
                "Password must be at least 8 characters and include both a letter and a digit."
            )
        user.password_hash = hash_password(new_password)
        self.repository.update(user)

    def request_password_reset(self, email: str) -> None:
        """
        Placeholder architecture for forgot-password (Part 4 scope: service +
        token issuance only). Actual email dispatch is wired up in
        Part 14 — Reports & Notifications.

        Always succeeds silently regardless of whether the email exists, to
        avoid leaking account existence via this endpoint.
        """
        user = self.repository.get_by_email(email)
        if user is None:
            return
        token = create_password_reset_token(subject=str(user.id))
        # TODO(Part 14): dispatch `token` via the notifications module instead
        # of doing nothing with it. Intentionally not logged/printed here to
        # avoid leaking a live reset token through application logs.

    def reset_password(self, token: str, new_password: str) -> None:
        try:
            payload = decode_token(token)
        except TokenError as exc:
            raise UnauthorizedError("Invalid or expired password reset token.") from exc

        if payload.get(CLAIM_TOKEN_TYPE) != TOKEN_TYPE_PASSWORD_RESET:
            raise UnauthorizedError("Token is not a password reset token.")

        user_id = parse_subject_uuid(payload.get(CLAIM_SUBJECT))
        user = self.repository.get_by_id(user_id) if user_id else None
        if not user or user.deleted_at is not None:
            raise UnauthorizedError("Invalid or expired password reset token.")

        if not is_strong_password(new_password):
            raise ValidationFailedError(
                "Password must be at least 8 characters and include both a letter and a digit."
            )
        user.password_hash = hash_password(new_password)
        self.repository.update(user)
