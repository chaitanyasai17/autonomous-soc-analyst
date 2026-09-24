"""
Report management endpoints — generate, list, and download SOC PDF/CSV reports.
"""

import os
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query, status
from fastapi.responses import FileResponse

from app.core.constants import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from app.core.exceptions import NotFoundError
from app.dependencies.auth import get_current_active_user
from app.dependencies.services import get_report_service
from app.models.enums import ReportType
from app.models.user import User
from app.schemas.base import PaginatedResponseSchema, ResponseSchema
from app.schemas.report import ReportGenerateRequest, ReportOut
from app.services.report_service import ReportService

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post(
    "/generate",
    response_model=ResponseSchema[ReportOut],
    status_code=status.HTTP_201_CREATED,
    summary="Generate a PDF or CSV report artifact",
)
def generate_report(
    data: ReportGenerateRequest,
    current_user: User = Depends(get_current_active_user),
    report_service: ReportService = Depends(get_report_service),
) -> ResponseSchema:
    report = report_service.generate_report(data, current_user)
    return ResponseSchema(
        success=True,
        message=f"{data.report_type.value.upper()} report '{data.report_name}' generated successfully.",
        data=report,
    )


@router.get(
    "",
    response_model=PaginatedResponseSchema[ReportOut],
    summary="List generated reports",
)
def list_reports(
    report_type: Optional[ReportType] = Query(default=None, description="Filter by report format (pdf, csv)"),
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=DEFAULT_PAGE_SIZE, ge=1, le=MAX_PAGE_SIZE),
    _current_user: User = Depends(get_current_active_user),
    report_service: ReportService = Depends(get_report_service),
) -> PaginatedResponseSchema:
    items, total = report_service.list_reports(
        report_type=report_type, skip=skip, limit=limit
    )
    return PaginatedResponseSchema(
        success=True,
        data=items,
        total=total,
        skip=skip,
        limit=limit,
    )


@router.get(
    "/{report_id}/download",
    summary="Download generated PDF or CSV report file",
)
def download_report(
    report_id: uuid.UUID,
    _current_user: User = Depends(get_current_active_user),
    report_service: ReportService = Depends(get_report_service),
):
    report = report_service.get_report_or_404(report_id)
    if not os.path.exists(report.file_path):
        raise NotFoundError("Report file artifact not found on storage disk.")

    media_type = "application/pdf" if report.report_type == ReportType.PDF else "text/csv"
    filename = os.path.basename(report.file_path)
    return FileResponse(
        path=report.file_path,
        media_type=media_type,
        filename=filename,
    )
