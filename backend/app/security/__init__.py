"""Authentication and authorization primitives: password hashing, JWT issuing/verification, RBAC permission checks. Consumed by dependencies/, not called directly by routes."""

from app.security.hashing import hash_password, verify_password
from app.security.jwt import (
    TokenError,
    create_access_token,
    create_password_reset_token,
    create_refresh_token,
    decode_token,
    parse_subject_uuid,
)
from app.security.permissions import Permission, ROLE_PERMISSIONS, role_has_permission

__all__ = [
    "hash_password",
    "verify_password",
    "create_access_token",
    "create_refresh_token",
    "create_password_reset_token",
    "decode_token",
    "parse_subject_uuid",
    "TokenError",
    "Permission",
    "ROLE_PERMISSIONS",
    "role_has_permission",
]

