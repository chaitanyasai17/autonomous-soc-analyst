"""
ASOC — FastAPI application root proxy entrypoint.
Exposes 'app' from app.main for standard entrypoint resolution.
"""

from app.main import app

__all__ = ["app"]
