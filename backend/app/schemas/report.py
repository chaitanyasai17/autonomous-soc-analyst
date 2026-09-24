"""
Report Pydantic schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Optional

from app.models.enums import ReportType
from app.schemas.base import BaseSchema


class ReportGenerateRequest(BaseSchema):
    report_name: str
    report_type: ReportType = ReportType.PDF
    scope: Optional[str] = "all"


class ReportOut(BaseSchema):
    id: uuid.UUID
    report_name: str
    report_type: ReportType
    generated_at: datetime
    file_path: str
    generated_by_id: Optional[uuid.UUID] = None
