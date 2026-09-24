"""CORS middleware configuration."""

from fastapi import FastAPI
from starlette.middleware.cors import CORSMiddleware

from app.config import get_settings


def add_cors_middleware(app: FastAPI) -> None:
    """Attach CORS middleware using origins from Settings."""
    settings = get_settings()
    allowed_origins = [str(origin) for origin in settings.CORS_ALLOWED_ORIGINS] or ["*"]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
