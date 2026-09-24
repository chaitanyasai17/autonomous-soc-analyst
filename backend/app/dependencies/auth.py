"""
Authentication dependencies.

`get_current_user` resolves and validates the bearer access token on every
protected route. `get_current_active_user` additionally enforces the
account is active and not soft-deleted — routes should depend on the latter
unless they have a specific reason to allow inactive users through.
"""

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer

from app.config import get_settings
from app.core.exceptions import UnauthorizedError
from app.dependencies.services import get_user_repository
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.security.constants import CLAIM_SUBJECT, CLAIM_TOKEN_TYPE, TOKEN_TYPE_ACCESS
from app.security.jwt import TokenError, decode_token, parse_subject_uuid

_settings = get_settings()

# tokenUrl points Swagger UI's "Authorize" button at the login endpoint.
# auto_error=False so a missing token raises OUR UnauthorizedError (standard
# ResponseSchema envelope) instead of FastAPI's default bare
# {"detail": "Not authenticated"} — keeps every auth failure consistently shaped.
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{_settings.API_V1_PREFIX}/auth/login", auto_error=False
)


def get_current_user(
    token: str | None = Depends(oauth2_scheme),
    user_repository: UserRepository = Depends(get_user_repository),
) -> User:
    """Decode the bearer token and load the corresponding User. Does not check is_active."""
    if token is None:
        raise UnauthorizedError("Not authenticated.")

    try:
        payload = decode_token(token)
    except TokenError as exc:
        raise UnauthorizedError("Invalid or expired authentication token.") from exc

    if payload.get(CLAIM_TOKEN_TYPE) != TOKEN_TYPE_ACCESS:
        raise UnauthorizedError("Token is not an access token.")

    user_id = parse_subject_uuid(payload.get(CLAIM_SUBJECT))
    if user_id is None:
        raise UnauthorizedError("Invalid authentication token.")

    user = user_repository.get_by_id(user_id)
    if user is None or user.deleted_at is not None:
        raise UnauthorizedError("User account no longer exists.")

    return user


def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Require the resolved user to be active. Use this for all protected routes."""
    if not current_user.is_active:
        raise UnauthorizedError("User account is inactive.")
    return current_user
