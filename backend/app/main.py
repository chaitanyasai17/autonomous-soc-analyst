"""
ASOC — FastAPI application entry point.

Run with (see backend/README.md for full instructions):
    uvicorn app.main:app --reload
"""

from fastapi import FastAPI

from app.api.v1.endpoints.health import router as health_router
from app.api.v1.router import api_router
from app.config import get_settings
from app.core.constants import API_TITLE, API_DESCRIPTION, API_VERSION
from app.core.exceptions import register_exception_handlers
from app.core.lifespan import lifespan
from app.middleware.registry import register_middleware

settings = get_settings()

app = FastAPI(
    title=API_TITLE,
    description=API_DESCRIPTION,
    version=API_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

register_middleware(app)
register_exception_handlers(app)

app.include_router(health_router)
app.include_router(api_router, prefix=settings.API_V1_PREFIX)
