"""
Risk scoring Pydantic schemas.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.models.enums import RiskLevel
from app.schemas.base import BaseSchema


class RiskFactorOut(BaseSchema):
    name: str
    impact: float
    detail: str


class RiskAssessmentOut(BaseSchema):
    id: uuid.UUID
    sigma_detection_id: Optional[uuid.UUID] = None
    risk_score: float
    risk_level: RiskLevel
    confidence: float
    calculated_at: datetime
    explanation: Optional[str] = None
    contributing_factors: Optional[List[RiskFactorOut]] = None


class RiskExplanationOut(BaseSchema):
    assessment_id: uuid.UUID
    detection_id: Optional[uuid.UUID] = None
    risk_score: float
    risk_level: RiskLevel
    confidence: float
    base_severity_score: float
    environmental_multiplier: float
    threat_intel_factor: float
    calculation_formula: str
    explanation: str
    contributing_factors: List[RiskFactorOut] = []


class RiskStatisticsOut(BaseSchema):
    total_assessments: int
    average_risk_score: float
    by_level: Dict[str, int]


class BatchRiskAssessmentOut(BaseSchema):
    assessed_count: int
    by_level: Dict[str, int]
    average_score: float
