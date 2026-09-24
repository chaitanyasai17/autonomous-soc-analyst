"""IOC Explorer API endpoints (Part 9)."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.dependencies.auth import get_current_active_user
from app.core.exceptions import NotFoundError
from app.dependencies.services import get_ioc_service
from app.models.user import User
from app.schemas.ioc import IOCRecordOut, IOCStatisticsOut
from app.services.ioc_service import IOCService

router = APIRouter(prefix="/iocs", tags=["Indicators of Compromise (IOCs)"])


@router.get("", response_model=dict)
def list_iocs(
    ioc_type: Optional[str] = Query(None, description="Filter by type (ipv4, ipv6, domain, hash, url, username, hostname)"),
    source: Optional[str] = Query(None, description="Filter by source"),
    search: Optional[str] = Query(None, description="Search indicator value or description"),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
    service: IOCService = Depends(get_ioc_service),
):
    items, total = service.list_iocs_enriched(ioc_type=ioc_type, source=source, search=search, skip=skip, limit=limit)
    return {
        "items": items,
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get("/statistics", response_model=IOCStatisticsOut)
def get_ioc_statistics(
    current_user: User = Depends(get_current_active_user),
    service: IOCService = Depends(get_ioc_service),
):
    stats = service.get_statistics()
    return IOCStatisticsOut(**stats)


@router.get("/{ioc_id}", response_model=dict)
def get_ioc(
    ioc_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    service: IOCService = Depends(get_ioc_service),
):
    graph = service.get_ioc_graph(ioc_id)
    return graph["ioc"]


@router.get("/{ioc_id}/graph", response_model=dict)
def get_ioc_graph(
    ioc_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    service: IOCService = Depends(get_ioc_service),
):
    """Retrieve full relationship graph: IOC -> Events -> Detections -> Alerts -> Incidents -> Endpoints."""
    return service.get_ioc_graph(ioc_id)

