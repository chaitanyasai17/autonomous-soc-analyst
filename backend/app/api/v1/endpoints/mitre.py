"""
MITRE ATT&CK endpoints — browse tactics, techniques, and ATT&CK matrix mappings.
"""

from typing import List, Optional

from fastapi import APIRouter, Depends, Query

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_mitre_service
from app.models.user import User
from app.schemas.base import PaginatedResponseSchema, ResponseSchema
from app.schemas.mitre import (
    MitreMatrixOut,
    MitreSeedResponse,
    MitreTacticOut,
    MitreTechniqueOut,
)
from app.services.mitre_service import MitreService

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])


@router.get(
    "/tactics",
    response_model=ResponseSchema[List[MitreTacticOut]],
    summary="List all MITRE ATT&CK Enterprise tactics",
)
def get_tactics(
    _current_user: User = Depends(get_current_active_user),
    mitre_service: MitreService = Depends(get_mitre_service),
) -> ResponseSchema:
    tactics = mitre_service.get_tactics()
    return ResponseSchema(success=True, data=tactics)


@router.get(
    "/matrix",
    response_model=ResponseSchema[MitreMatrixOut],
    summary="Get full MITRE ATT&CK Enterprise matrix with active detection counts",
)
def get_matrix(
    _current_user: User = Depends(get_current_active_user),
    mitre_service: MitreService = Depends(get_mitre_service),
) -> ResponseSchema:
    matrix = mitre_service.get_matrix()
    return ResponseSchema(success=True, data=matrix)


@router.get(
    "/techniques",
    response_model=PaginatedResponseSchema[MitreTechniqueOut],
    summary="List and search MITRE ATT&CK techniques",
)
def list_techniques(
    tactic: Optional[str] = Query(default=None, description="Filter by tactic slug (e.g. execution)"),
    search: Optional[str] = Query(default=None, description="Search by ID, name, or description"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    _current_user: User = Depends(get_current_active_user),
    mitre_service: MitreService = Depends(get_mitre_service),
) -> PaginatedResponseSchema:
    items, total = mitre_service.list_techniques(
        tactic=tactic, search=search, skip=skip, limit=limit
    )
    return PaginatedResponseSchema(
        success=True,
        data=items,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/techniques/{technique_id}",
    response_model=ResponseSchema[MitreTechniqueOut],
    summary="Get MITRE ATT&CK technique details by technique ID (e.g. T1218)",
)
def get_technique(
    technique_id: str,
    _current_user: User = Depends(get_current_active_user),
    mitre_service: MitreService = Depends(get_mitre_service),
) -> ResponseSchema:
    technique = mitre_service.get_technique(technique_id)
    det_count = mitre_service._get_detection_count_for_technique(technique.id)
    data = MitreTechniqueOut(
        id=technique.id,
        technique_id=technique.technique_id,
        technique_name=technique.technique_name,
        tactic=technique.tactic,
        description=technique.description,
        reference_url=technique.reference_url,
        detection_count=det_count,
    )
    return ResponseSchema(success=True, data=data)


@router.post(
    "/seed",
    response_model=ResponseSchema[MitreSeedResponse],
    summary="Seed MITRE ATT&CK knowledge base catalog",
)
def seed_catalog(
    _current_user: User = Depends(get_current_active_user),
    mitre_service: MitreService = Depends(get_mitre_service),
) -> ResponseSchema:
    count = mitre_service.seed_if_empty()
    return ResponseSchema(
        success=True,
        message="MITRE ATT&CK catalog seeded.",
        data=MitreSeedResponse(
            techniques_seeded=count,
            message=f"{count} techniques initialized in catalog.",
        ),
    )


@router.get(
    "/search",
    response_model=ResponseSchema[List[MitreTechniqueOut]],
    summary="Search MITRE ATT&CK techniques by keyword or identifier",
)
def search_mitre(
    q: str = Query(..., min_length=1, description="Search query string"),
    _current_user: User = Depends(get_current_active_user),
    mitre_service: MitreService = Depends(get_mitre_service),
) -> ResponseSchema:
    items, total = mitre_service.list_techniques(search=q, limit=50)
    return ResponseSchema(success=True, message=f"Found {total} technique(s)", data=items)
