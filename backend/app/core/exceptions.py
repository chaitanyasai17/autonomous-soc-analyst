"""
Custom application exceptions and global exception handlers.

Domain/service-layer code should raise the exceptions defined here rather
than raising `HTTPException` directly, so that HTTP-specific concerns stay
out of the service layer (Clean Architecture: services must not depend on
the presentation layer).
"""

import logging

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)


class ASOCException(Exception):
    """Base class for all application-raised exceptions."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    message: str = "An unexpected error occurred."

    def __init__(self, message: str | None = None):
        self.message = message or self.message
        super().__init__(self.message)


class NotFoundError(ASOCException):
    """Raised when a requested resource does not exist."""

    status_code = status.HTTP_404_NOT_FOUND
    message = "Resource not found."


class ConflictError(ASOCException):
    """Raised when an operation conflicts with existing state (e.g., duplicate)."""

    status_code = status.HTTP_409_CONFLICT
    message = "Conflict with current state."


class ValidationFailedError(ASOCException):
    """Raised for domain-level validation failures not caught by Pydantic."""

    status_code = getattr(status, "HTTP_422_UNPROCESSABLE_CONTENT", 422)
    message = "Validation failed."


class UnauthorizedError(ASOCException):
    """Raised when authentication is required but missing/invalid."""

    status_code = status.HTTP_401_UNAUTHORIZED
    message = "Authentication required."


class ForbiddenError(ASOCException):
    """Raised when the authenticated principal lacks permission (RBAC, Part 4)."""

    status_code = status.HTTP_403_FORBIDDEN
    message = "You do not have permission to perform this action."


PermissionDeniedError = ForbiddenError



def _error_body(message: str, details: object | None = None) -> dict:
    body: dict = {"success": False, "message": message}
    if details is not None:
        body["details"] = details
    return body


def register_exception_handlers(app: FastAPI) -> None:
    """Register global exception handlers on the FastAPI app instance."""

    @app.exception_handler(ASOCException)
    async def asoc_exception_handler(request: Request, exc: ASOCException) -> JSONResponse:
        logger.warning("Handled ASOCException: %s (%s)", exc.message, request.url.path)
        return JSONResponse(status_code=exc.status_code, content=_error_body(exc.message))

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        logger.info("Request validation failed: %s", request.url.path)
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content=_error_body("Request validation failed.", details=exc.errors()),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("Unhandled exception on %s", request.url.path)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=_error_body("Internal server error."),
        )
