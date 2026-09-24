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
app.include_router(health_router, prefix="/api", include_in_schema=False)
app.include_router(health_router, prefix=settings.API_V1_PREFIX)
app.include_router(api_router, prefix=settings.API_V1_PREFIX)
app.include_router(api_router, prefix="/api", include_in_schema=False)


@app.get("/api/docs", include_in_schema=False)
def api_docs():
    from fastapi.openapi.docs import get_swagger_ui_html
    return get_swagger_ui_html(openapi_url="/api/openapi.json", title=f"{API_TITLE} - Swagger UI")


@app.get("/api/redoc", include_in_schema=False)
def api_redoc():
    from fastapi.openapi.docs import get_redoc_html
    return get_redoc_html(openapi_url="/api/openapi.json", title=f"{API_TITLE} - ReDoc")


@app.get("/api/openapi.json", include_in_schema=False)
def api_openapi():
    from fastapi.responses import JSONResponse
    return JSONResponse(app.openapi())
