"""Web Security Lab API endpoints (Part 15)."""

from __future__ import annotations

import uuid
from typing import List, Optional

from fastapi import APIRouter, Depends, Query, status

from app.dependencies.auth import get_current_active_user
from app.core.exceptions import PermissionDeniedError
from app.dependencies.services import get_audit_service, get_web_security_service
from app.models.enums import RiskLevel, UserRole
from app.models.user import User
from app.schemas.alert import AlertOut
from app.schemas.web_security import (
    AllowlistCreateRequest,
    AllowlistEntryOut,
    AllowlistUpdateRequest,
    PostureScoreOut,
    ScanComparisonOut,
    ScanLaunchRequest,
    TopVulnerableEndpointOut,
    WebSecurityFindingOut,
    WebSecurityScanOut,
)
from app.services.audit_service import AuditService
from app.services.web_security_service import WebSecurityService

router = APIRouter(prefix="/web-security", tags=["Web Application Security Lab"])


@router.post("/scans", response_model=WebSecurityScanOut, status_code=status.HTTP_201_CREATED)
def launch_scan(
    req: ScanLaunchRequest,
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
    audit_service: AuditService = Depends(get_audit_service),
):
    """Launch an authorized defensive web application security audit."""
    result = service.launch_scan(req, user=current_user)
    audit_service.log(
        action="SECURITY_SCAN_RUN",
        user=current_user,
        object_type="WEB_SECURITY_SCAN",
        object_id=result.scan_id,
        details={"target": req.target_url, "profile": req.scan_profile},
    )
    return result


@router.get("/scans", response_model=dict)
def list_scans(
    target_host: Optional[str] = Query(None, description="Filter by target host"),
    status: Optional[str] = Query(None, description="Filter by status (completed, running, failed)"),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    items, total = service.list_scans(target_host=target_host, status=status, skip=skip, limit=limit)
    return {
        "items": [item.model_dump() for item in items],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get("/scans/{scan_id}", response_model=WebSecurityScanOut)
def get_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    return service.get_scan(scan_id)


@router.post("/scans/{scan_id}/cancel", response_model=WebSecurityScanOut)
def cancel_scan(
    scan_id: str,
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    """Cancel an in-progress scan."""
    return service.cancel_scan(scan_id, user=current_user)


@router.get("/scans/{scan_id}/findings", response_model=dict)
def get_scan_findings(
    scan_id: uuid.UUID,
    severity: Optional[RiskLevel] = Query(None),
    category: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    items, total = service.get_scan_findings(
        scan_id=scan_id,
        severity=severity,
        category=category,
        status=status,
        search=search,
        skip=skip,
        limit=limit,
    )
    return {
        "items": [item.model_dump() for item in items],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.get("/findings/{finding_id}", response_model=WebSecurityFindingOut)
def get_finding(
    finding_id: str,
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    return service.get_finding(finding_id)


@router.post("/findings/{finding_id}/promote-to-alert", response_model=AlertOut)
def promote_finding_to_alert(
    finding_id: str,
    auto_correlate: bool = Query(True, description="Automatically correlate with active incidents"),
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    """
    Promote a defensive web finding into an actionable SOC alert.
    Integrates directly into Risk Engine, IOC repository, and Incident Correlation.
    """
    return service.promote_finding_to_alert(finding_id, user=current_user, auto_correlate=auto_correlate)


@router.post("/findings/{finding_id}/promote", response_model=AlertOut)
def promote_finding_alias(
    finding_id: str,
    auto_correlate: bool = Query(True, description="Automatically correlate with active incidents"),
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    """Alias for /findings/{finding_id}/promote-to-alert."""
    return service.promote_finding_to_alert(finding_id, user=current_user, auto_correlate=auto_correlate)


@router.get("/statistics", response_model=dict)
def get_statistics(
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    return service.get_scan_statistics()


@router.get("/history", response_model=List[WebSecurityScanOut])
def get_history(
    target_host: Optional[str] = Query(None),
    limit: int = Query(10, ge=1, le=50),
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    return service.get_scan_history(target_host=target_host, limit=limit)


@router.get("/posture", response_model=PostureScoreOut)
def get_posture_summary(
    target_host: Optional[str] = Query(None, description="Optional target host to scope posture score"),
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    return service.get_posture_summary(target_host=target_host)


@router.get("/compare", response_model=ScanComparisonOut)
def compare_scans(
    target_host: str = Query(..., description="Target host to compare scans for"),
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    return service.compare_scans(target_host=target_host)


@router.get("/top-vulnerable-endpoints", response_model=List[TopVulnerableEndpointOut])
def get_top_vulnerable_endpoints(
    limit: int = Query(5, ge=1, le=20),
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    return service.get_top_vulnerable_endpoints(limit=limit)


# --- Allowlist Management ---

@router.get("/allowlist", response_model=dict)
def list_allowlist(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    items, total = service.list_allowlist(skip=skip, limit=limit)
    return {
        "items": [item.model_dump() for item in items],
        "total": total,
        "skip": skip,
        "limit": limit,
    }


@router.post("/allowlist", response_model=AllowlistEntryOut, status_code=status.HTTP_201_CREATED)
def create_allowlist_entry(
    req: AllowlistCreateRequest,
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise PermissionDeniedError("Only administrators can configure the Target Allowlist.")
    return service.create_allowlist_entry(req, user=current_user)


@router.patch("/allowlist/{entry_id}", response_model=AllowlistEntryOut)
def update_allowlist_entry(
    entry_id: uuid.UUID,
    req: AllowlistUpdateRequest,
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise PermissionDeniedError("Only administrators can modify the Target Allowlist.")
    return service.update_allowlist_entry(entry_id, req)


@router.delete("/allowlist/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_allowlist_entry(
    entry_id: uuid.UUID,
    current_user: User = Depends(get_current_active_user),
    service: WebSecurityService = Depends(get_web_security_service),
):
    if current_user.role not in (UserRole.ADMIN, UserRole.SUPER_ADMIN):
        raise PermissionDeniedError("Only administrators can remove entries from the Target Allowlist.")
    service.delete_allowlist_entry(entry_id)
    return None
