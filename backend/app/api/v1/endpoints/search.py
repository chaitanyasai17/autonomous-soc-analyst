"""
Global Search endpoint — Cross-entity intelligence search.
"""

from typing import Any, Dict

from fastapi import APIRouter, Depends, Query

from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_global_search_service
from app.models.user import User
from app.schemas.base import ResponseSchema
from app.services.global_search_service import GlobalSearchService

router = APIRouter(prefix="/search", tags=["Global Search"])


@router.get(
    "",
    response_model=ResponseSchema[Dict[str, Any]],
    summary="Global cross-entity search across incidents, alerts, detections, IOCs, events, and MITRE techniques",
)
def global_search(
    q: str = Query(default="", description="Search query string"),
    limit: int = Query(default=5, ge=1, le=20, description="Max results per category"),
    current_user: User = Depends(get_current_active_user),
    search_service: GlobalSearchService = Depends(get_global_search_service),
) -> ResponseSchema:
    results = search_service.search(query_str=q, limit_per_type=limit)
    return ResponseSchema(success=True, data=results)
