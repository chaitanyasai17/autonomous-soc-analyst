"""
Middleware registration.

Single place that wires up every middleware onto the FastAPI app, in the
correct order. `main.py` calls only this function, keeping middleware
ordering concerns out of the entry point.

Note: Starlette applies middleware in reverse order of registration (the
last-added middleware runs first on the request path). Timing wraps
everything so it captures true end-to-end duration.
"""

from fastapi import FastAPI

from app.middleware.cors import add_cors_middleware
from app.middleware.request_logging import RequestLoggingMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.timing import RequestTimingMiddleware


def register_middleware(app: FastAPI) -> None:
    """Register all application middleware in the intended execution order."""
    add_cors_middleware(app)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RequestTimingMiddleware)
