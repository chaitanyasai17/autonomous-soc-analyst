"""
API v1 router aggregator.

Every new resource router added in later parts (auth, users, logs, alerts,
incidents, etc.) gets included here — this is the ONLY file that needs
touching to expose a new v1 endpoint group.

IMPORTANT — registration order under a shared prefix: FastAPI/Starlette
match a route's path TEMPLATE structurally first (e.g. "/logs/{log_id}"
matches any single non-slash segment); the {log_id} parameter is only
converted to uuid.UUID *after* that route is selected, so a non-UUID
literal segment like "statistics" or "bulk-delete" does NOT automatically
fall through to a more specific route — it fails UUID validation on
whichever matching route was registered first. This is the same lesson as
Part 4's /users/me: log_management.router's literal sub-paths (/bulk-delete,
/bulk-reparse, /bulk-status, /statistics) MUST be registered before
logs.router's generic /{log_id} route, or they'd 422 as invalid UUIDs.
"""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    ai,
    alerts,
    audit_logs,
    auth,
    dashboard,
    detections,
    endpoints,
    health,
    incidents,
    iocs,
    log_management,
    logs,
    mitre,
    notifications,
    parsing,
    pipeline,
    reports,
    risk,
    search,
    sigma_rules,
    soc_health,
    timeline,
    users,
    web_security,
)

api_router = APIRouter()

api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(dashboard.router)
api_router.include_router(log_management.router)
api_router.include_router(logs.router)
api_router.include_router(parsing.router)
api_router.include_router(parsing.parsed_logs_router)
api_router.include_router(sigma_rules.router)
api_router.include_router(detections.router)
api_router.include_router(mitre.router)
api_router.include_router(ai.router)
api_router.include_router(risk.router)
api_router.include_router(alerts.router)
api_router.include_router(incidents.router)
api_router.include_router(reports.router)
api_router.include_router(notifications.router)
api_router.include_router(web_security.router)
api_router.include_router(iocs.router)
api_router.include_router(soc_health.router)
api_router.include_router(audit_logs.router)
api_router.include_router(audit_logs.audit_alias_router)
api_router.include_router(pipeline.router)
api_router.include_router(search.router)
api_router.include_router(endpoints.router)
api_router.include_router(timeline.router)


