"""SOC Health Diagnostics API endpoint (Part 16)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_soc_health_service
from app.models.user import User
from app.schemas.soc_health import SOCHealthReportOut
from app.services.soc_health_service import SOCHealthService

router = APIRouter(prefix="/soc-health", tags=["SOC Health & Diagnostics"])


@router.get("", response_model=SOCHealthReportOut)
def get_soc_health(
    current_user: User = Depends(get_current_active_user),
    service: SOCHealthService = Depends(get_soc_health_service),
):
    """Run real-time diagnostics on all 13 core SOC engines."""
    return service.check_all_components()
