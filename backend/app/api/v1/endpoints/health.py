"""Health check endpoint — liveness/readiness probe for ASOC."""

from fastapi import APIRouter

from app.config import get_settings
from app.core.constants import API_VERSION
from app.schemas.base import ResponseSchema

router = APIRouter(tags=["Health"])


class HealthData(dict):
    """Lightweight typed dict-like payload for the health response."""


@router.get("/health", response_model=ResponseSchema, summary="Health check")
def health_check() -> ResponseSchema:
    """Return service status, environment, and API version."""
    settings = get_settings()
    return ResponseSchema(
        success=True,
        message="ASOC API is healthy.",
        data={
            "status": "ok",
            "environment": settings.APP_ENV.value,
            "version": API_VERSION,
        },
    )
