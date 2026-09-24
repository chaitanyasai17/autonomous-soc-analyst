"""FastAPI dependency-injection providers (e.g., get_db, get_current_user). Wires security/ and database/ into route handlers."""

from app.dependencies.auth import get_current_active_user, get_current_user
from app.dependencies.database import get_db
from app.dependencies.rbac import require_permissions, require_roles
from app.dependencies.services import (
    get_auth_service,
    get_detection_engine,
    get_detection_service,
    get_file_storage,
    get_log_management_service,
    get_parsed_log_repository,
    get_parser_service,
    get_rule_loader,
    get_rule_service,
    get_security_log_repository,
    get_sigma_detection_repository,
    get_upload_service,
    get_user_repository,
    get_user_service,
)

__all__ = [
    "get_db",
    "get_current_user",
    "get_current_active_user",
    "require_roles",
    "require_permissions",
    "get_user_repository",
    "get_user_service",
    "get_auth_service",
    "get_security_log_repository",
    "get_file_storage",
    "get_upload_service",
    "get_parsed_log_repository",
    "get_parser_service",
    "get_log_management_service",
    "get_rule_loader",
    "get_detection_engine",
    "get_rule_service",
    "get_sigma_detection_repository",
    "get_detection_service",
]

