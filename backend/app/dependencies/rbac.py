"""
RBAC dependency factories.

Deliberately generic: neither function knows the names of any specific
role or permission. Adding a new role/permission never requires touching
this file — only app/security/permissions.py.
"""

from fastapi import Depends

from app.core.exceptions import ForbiddenError
from app.dependencies.auth import get_current_active_user
from app.models.enums import UserRole
from app.models.user import User
from app.security.permissions import Permission, role_has_permission


def require_roles(*allowed_roles: UserRole):
    """Dependency factory: allow only the given roles through."""

    def dependency(current_user: User = Depends(get_current_active_user)) -> User:
        if current_user.role not in allowed_roles:
            raise ForbiddenError("You do not have permission to perform this action.")
        return current_user

    return dependency


def require_permissions(*required_permissions: Permission):
    """Dependency factory: allow only users whose role holds ALL given permissions."""

    def dependency(current_user: User = Depends(get_current_active_user)) -> User:
        if not all(
            role_has_permission(current_user.role, perm) for perm in required_permissions
        ):
            raise ForbiddenError("You do not have permission to perform this action.")
        return current_user

    return dependency
