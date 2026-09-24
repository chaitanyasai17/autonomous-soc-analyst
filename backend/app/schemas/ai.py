"""
AI Threat Analysis Pydantic schemas.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.schemas.base import BaseSchema


class IOCItem(BaseSchema):
    type: str
    value: str
    description: Optional[str] = None


class AIThreatAnalysisResponse(BaseSchema):
    threat_summary: str
    attack_narrative: str
    confidence: float
    false_positive_likelihood: str
    false_positive_rationale: Optional[str] = None
    recommended_actions: List[str]
    indicators_of_compromise: List[IOCItem] = []
    mitre_alignment: List[str] = []
    provider_used: str


class AIProviderStatus(BaseSchema):
    provider: str
    model: str
    status: str
    is_available: bool
    fallback_available: bool
    message: str


class AIAnalysisRequest(BaseSchema):
    custom_notes: Optional[str] = None
