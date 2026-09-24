"""Endpoints API — host management, monitoring, containment, and telemetry correlation."""

from __future__ import annotations

import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query, status

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_endpoint_service
from app.models.enums import RiskLevel
from app.models.user import User
from app.schemas.base import PaginatedResponseSchema, ResponseSchema
from app.schemas.endpoint import (
    EndpointCreate,
    EndpointDetailOut,
    EndpointIsolateRequest,
    EndpointOut,
    EndpointStatisticsOut,
)
from app.services.endpoint_service import EndpointService

router = APIRouter(prefix="/endpoints", tags=["Endpoints Management"])


@router.get(
    "",
    response_model=PaginatedResponseSchema[EndpointOut],
    summary="List authorized endpoints (paginated, filterable, ownership-scoped)",
)
def list_endpoints(
    status: Optional[str] = Query(default=None, description="Filter by status (online, offline, degraded)"),
    risk_level: Optional[RiskLevel] = Query(default=None, description="Filter by risk level"),
    search: Optional[str] = Query(default=None, description="Search hostname, IP, or OS"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    current_user: User = Depends(get_current_active_user),
    service: EndpointService = Depends(get_endpoint_service),
) -> PaginatedResponseSchema[EndpointOut]:
    items, total = service.list_endpoints(
        current_user=current_user,
        status=status,
        risk_level=risk_level,
        search_query=search,
        skip=skip,
        limit=limit,
    )
    return PaginatedResponseSchema(
        success=True,
        message=f"Retrieved {len(items)} endpoint(s).",
        data=items,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/statistics",
    response_model=ResponseSchema[EndpointStatisticsOut],
    summary="Get operational endpoint counts and risk breakdown",
)
def get_endpoint_statistics(
    current_user: User = Depends(get_current_active_user),
    service: EndpointService = Depends(get_endpoint_service),
) -> ResponseSchema[EndpointStatisticsOut]:
    stats = service.get_statistics(current_user)
    return ResponseSchema(success=True, message="Endpoint statistics retrieved.", data=stats)


@router.post(
    "",
    response_model=ResponseSchema[EndpointOut],
    status_code=status.HTTP_201_CREATED,
    summary="Register a new authorized endpoint into the SOC",
)
def register_endpoint(
    data: EndpointCreate,
    current_user: User = Depends(get_current_active_user),
    service: EndpointService = Depends(get_endpoint_service),
) -> ResponseSchema[EndpointOut]:
    endpoint = service.register_endpoint(data, current_user)
    return ResponseSchema(
        success=True,
        message=f"Endpoint '{endpoint.hostname}' successfully registered.",
        data=endpoint,
    )


@router.get(
    "/{endpoint_id}",
    response_model=ResponseSchema[EndpointDetailOut],
    summary="Get endpoint telemetry, recent events, detections, and alerts",
)
def get_endpoint_detail(
    endpoint_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    service: EndpointService = Depends(get_endpoint_service),
) -> ResponseSchema[EndpointDetailOut]:
    detail = service.get_endpoint_detail(endpoint_id, current_user)
    return ResponseSchema(success=True, message="Endpoint details retrieved.", data=detail)


@router.post(
    "/{endpoint_id}/isolate",
    response_model=ResponseSchema[EndpointOut],
    summary="Isolate or reconnect an endpoint for incident containment",
)
def set_endpoint_isolation(
    endpoint_id: uuid.UUID,
    request: EndpointIsolateRequest,
    current_user: User = Depends(get_current_active_user),
    service: EndpointService = Depends(get_endpoint_service),
) -> ResponseSchema[EndpointOut]:
    endpoint = service.set_isolation(endpoint_id, request, current_user)
    action_text = "isolated from network" if request.is_isolated else "reconnected to network"
    return ResponseSchema(
        success=True,
        message=f"Endpoint '{endpoint.hostname}' {action_text}.",
        data=endpoint,
    )


@router.delete(
    "/{endpoint_id}",
    status_code=status.HTTP_200_OK,
    response_model=ResponseSchema[dict],
    summary="Remove an authorized endpoint from monitoring",
)
def remove_endpoint(
    endpoint_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    service: EndpointService = Depends(get_endpoint_service),
) -> ResponseSchema[dict]:
    service.delete_endpoint(endpoint_id, current_user)
    return ResponseSchema(
        success=True,
        message="Endpoint removed successfully.",
        data={"id": str(endpoint_id)},
    )
