"""Authentication endpoints — register, login, refresh, logout, password management, current user."""

from fastapi import APIRouter, Depends, status
from fastapi.security import OAuth2PasswordRequestForm

from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_audit_service, get_auth_service
from app.models.user import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    LogoutRequest,
    RefreshTokenRequest,
    ResetPasswordRequest,
    TokenResponse,
)
from app.schemas.base import ResponseSchema
from app.schemas.user import PasswordChangeRequest, UserCreate, UserOut
from app.services.audit_service import AuditService
from app.services.auth_service import AuthService

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=ResponseSchema[UserOut],
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
)
def register(
    data: UserCreate, auth_service: AuthService = Depends(get_auth_service)
) -> ResponseSchema:
    user = auth_service.register(data)
    return ResponseSchema(success=True, message="Registration successful.", data=user)


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Log in and receive an access/refresh token pair",
)
def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    auth_service: AuthService = Depends(get_auth_service),
    audit_service: AuditService = Depends(get_audit_service),
) -> TokenResponse:
    tokens = auth_service.login(form_data.username, form_data.password)
    user = auth_service.repository.get_by_username(form_data.username)
    if user:
        audit_service.log(
            action="USER_LOGIN",
            user=user,
            object_type="USER",
            object_id=str(user.id),
            details={"username": user.username, "role": user.role.value if hasattr(user.role, "value") else str(user.role)},
        )
    return tokens


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Exchange a refresh token for a new access/refresh token pair",
)
def refresh_token(
    data: RefreshTokenRequest, auth_service: AuthService = Depends(get_auth_service)
) -> TokenResponse:
    return auth_service.refresh(data.refresh_token)


@router.post(
    "/logout",
    response_model=ResponseSchema,
    summary="Revoke a refresh token",
)
def logout(
    data: LogoutRequest,
    auth_service: AuthService = Depends(get_auth_service),
    audit_service: AuditService = Depends(get_audit_service),
    current_user: User = Depends(get_current_active_user),
) -> ResponseSchema:
    auth_service.logout(data.refresh_token)
    audit_service.log(
        action="USER_LOGOUT",
        user=current_user,
        object_type="USER",
        object_id=str(current_user.id),
    )
    return ResponseSchema(success=True, message="Logged out successfully.")


@router.post(
    "/change-password",
    response_model=ResponseSchema,
    summary="Change the current user's password",
)
def change_password(
    data: PasswordChangeRequest,
    current_user: User = Depends(get_current_active_user),
    auth_service: AuthService = Depends(get_auth_service),
) -> ResponseSchema:
    auth_service.change_password(current_user, data.current_password, data.new_password)
    return ResponseSchema(success=True, message="Password changed successfully.")


@router.post(
    "/forgot-password",
    response_model=ResponseSchema,
    summary="Request a password reset (architecture placeholder — email dispatch is Part 14)",
)
def forgot_password(
    data: ForgotPasswordRequest, auth_service: AuthService = Depends(get_auth_service)
) -> ResponseSchema:
    auth_service.request_password_reset(data.email)
    # Always the same response, regardless of whether the email exists.
    return ResponseSchema(
        success=True, message="If that email is registered, a reset link has been sent."
    )


@router.post(
    "/reset-password",
    response_model=ResponseSchema,
    summary="Reset a password using a password reset token",
)
def reset_password(
    data: ResetPasswordRequest, auth_service: AuthService = Depends(get_auth_service)
) -> ResponseSchema:
    auth_service.reset_password(data.token, data.new_password)
    return ResponseSchema(success=True, message="Password reset successfully.")


@router.get(
    "/me",
    response_model=ResponseSchema[UserOut],
    summary="Get the currently authenticated user",
)
def get_me(current_user: User = Depends(get_current_active_user)) -> ResponseSchema:
    return ResponseSchema(success=True, data=current_user)
