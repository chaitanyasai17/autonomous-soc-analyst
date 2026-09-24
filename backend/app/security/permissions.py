"""
RBAC permission model.

Design goal (per Part 4 spec): adding a new role or permission later must
never require touching dependencies/, endpoints, or services — only this
file. Two things make that possible:

    1. `Permission` is a flat enum of fine-grained capabilities.
    2. `ROLE_PERMISSIONS` maps each `UserRole` to the set of permissions it
       holds. Roles are built by *composing* lower roles' permission sets
       (e.g., ADMIN = SOC_MANAGER's permissions + a few more), so adding a
       permission to a "tier" automatically propagates to every higher role
       without editing each one individually.

`app/dependencies/rbac.py` reads this mapping generically — it has no
knowledge of specific roles or permissions.
"""

import enum

from app.models.enums import UserRole


class Permission(str, enum.Enum):
    """Fine-grained capabilities checkable independently of role names."""

    # --- Self-service (every authenticated, active user) ---
    USER_READ_SELF = "user:read:self"
    USER_UPDATE_SELF = "user:update:self"

    # --- User management (elevated roles) ---
    USER_LIST = "user:list"
    USER_READ_ANY = "user:read:any"
    USER_UPDATE_ANY = "user:update:any"
    USER_MANAGE_ROLES = "user:manage:roles"
    USER_DEACTIVATE = "user:deactivate"
    USER_DELETE = "user:delete"
    USER_RESTORE = "user:restore"

    # --- Log upload (Part 5) ---
    LOG_UPLOAD = "log:upload"
    # Note: viewing one's OWN uploads needs no permission (same pattern as
    # USER_READ_SELF/self-profile in Part 4) — LOG_READ_ANY governs
    # visibility into OTHER users' uploads; ownership is checked separately.
    LOG_READ_ANY = "log:read:any"
    LOG_DELETE = "log:delete"

    # --- Log parsing (Part 6) ---
    # LOG_PARSE: baseline capability to trigger parsing at all (own uploads).
    # LOG_PARSE_ANY: elevated capability to trigger parsing on ANY user's
    # upload. Kept separate from LOG_READ_ANY on purpose — read-only roles
    # (Viewer) must never be able to trigger a write/compute action just
    # because they can see everyone's logs.
    LOG_PARSE = "log:parse"
    LOG_PARSE_ANY = "log:parse:any"

    # --- Sigma detection engine (Part 8) ---
    # Exact permission strings mandated by the Part 8 spec. Note SIGMA_RUN
    # (own files) does not by itself grant visibility into other users'
    # logs — running detection on someone else's parsed logs additionally
    # requires LOG_READ_ANY, exactly mirroring the LOG_PARSE/LOG_PARSE_ANY
    # split from Part 6, but reusing LOG_READ_ANY rather than inventing a
    # fifth sigma permission, since the spec enumerates exactly four.
    SIGMA_VIEW = "sigma:view"
    SIGMA_RUN = "sigma:run"
    SIGMA_RELOAD = "sigma:reload"
    SIGMA_MANAGE = "sigma:manage"


# Built per-role by composing the tier below, since VIEWER and ANALYST now
# diverge on log permissions (a Viewer can see all logs but never upload;
# an Analyst can upload but, unlike a Viewer, doesn't automatically see
# everyone else's uploads — see app/services/upload_service.py for how
# LOG_READ_ANY vs. resource ownership are combined at query time).
_VIEWER_PERMS: set[Permission] = {
    Permission.USER_READ_SELF,
    Permission.USER_UPDATE_SELF,
    Permission.LOG_READ_ANY,
    Permission.SIGMA_VIEW,
}

_ANALYST_PERMS: set[Permission] = {
    Permission.USER_READ_SELF,
    Permission.USER_UPDATE_SELF,
    Permission.LOG_UPLOAD,
    Permission.LOG_PARSE,
    Permission.SIGMA_VIEW,
    Permission.SIGMA_RUN,
}

_SOC_MANAGER_PERMS: set[Permission] = _ANALYST_PERMS | {
    Permission.USER_LIST,
    Permission.USER_READ_ANY,
    Permission.LOG_READ_ANY,
    Permission.LOG_DELETE,
    Permission.LOG_PARSE_ANY,
    Permission.SIGMA_RELOAD,
}

_ADMIN_PERMS: set[Permission] = _SOC_MANAGER_PERMS | {
    Permission.USER_UPDATE_ANY,
    Permission.USER_MANAGE_ROLES,
    Permission.USER_DEACTIVATE,
    Permission.USER_DELETE,
    Permission.USER_RESTORE,
    Permission.SIGMA_MANAGE,
}

ROLE_PERMISSIONS: dict[UserRole, set[Permission]] = {
    UserRole.VIEWER: _VIEWER_PERMS,
    UserRole.ANALYST: _ANALYST_PERMS,
    UserRole.SOC_MANAGER: _SOC_MANAGER_PERMS,
    UserRole.ADMIN: _ADMIN_PERMS,
    # Super Admin holds every permission that exists, by definition — kept
    # as an explicit superset rather than a "bypass all checks" special
    # case, so it still goes through the same permission-checking path.
    UserRole.SUPER_ADMIN: set(Permission),
}


def role_has_permission(role: UserRole, permission: Permission) -> bool:
    """Check whether a role holds a given permission."""
    return permission in ROLE_PERMISSIONS.get(role, set())
