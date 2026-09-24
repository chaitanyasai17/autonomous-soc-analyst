"""Detection API response schemas."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import Field

from app.models.enums import RiskLevel
from app.schemas.base import BaseSchema


class MatchedFieldOut(BaseSchema):
    field: str
    value: str
    selection: str


class SigmaDetectionOut(BaseSchema):
    """Public representation of a single Sigma detection."""

    id: uuid.UUID
    parsed_log_id: uuid.UUID
    matched_rule: str
    rule_title: str
    rule_category: str | None = None
    rule_tags: list[str] | None = None
    severity: RiskLevel
    confidence: float
    matched_fields: list[dict] | None = None
    detection_timestamp: datetime
    created_at: datetime
    analyst_verdict: Optional[str] = None
    analyst_note: Optional[str] = None


class DetectionEvidenceOut(BaseSchema):
    detection_id: uuid.UUID
    rule_id: str
    rule_title: str
    severity: RiskLevel
    confidence: float
    matched_fields: List[Dict[str, Any]]
    rule_condition: Optional[str] = None
    log_payload: Optional[Dict[str, Any]] = None
    mitre_techniques: List[Dict[str, str]] = []
    explanation: str


class DetectionFeedbackRequest(BaseSchema):
    verdict: str  # TRUE_POSITIVE, FALSE_POSITIVE, BENIGN_SUSPICIOUS
    note: Optional[str] = None


class DetectionQualityMetricsOut(BaseSchema):
    total_detections: int
    reviewed_detections: int
    true_positives: int
    false_positives: int
    benign_suspicious: int
    tp_rate: float
    fp_rate: float
    accuracy: float


class DetectionRunSummary(BaseSchema):
    """Returned by the run/run-file/run-all detection endpoints."""

    events_scanned: int
    detections_created: int
    detections_skipped_duplicate: int
    by_severity: dict[str, int] = Field(default_factory=dict)


class DetectionStatistics(BaseSchema):
    """Returned by GET /detections/statistics."""

    total_detections: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    top_rules: list[dict]
    average_confidence: float
    last_detection_at: datetime | None


class DetectionAnalyticsOut(BaseSchema):
    """Returned by GET /detections/analytics."""

    total_detections: int
    by_severity: dict[str, int]
    by_category: dict[str, int]
    top_rules: list[dict]
    top_mitre_techniques: list[dict]
    detections_by_endpoint: list[dict]
    daily_trend: list[dict]
    quality_metrics: DetectionQualityMetricsOut
    average_confidence: float
    last_detection_at: datetime | None
