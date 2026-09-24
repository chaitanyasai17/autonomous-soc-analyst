"""
Risk Scoring Service — runs deterministic risk scoring and persists RiskAssessment entities.
"""

from __future__ import annotations

import logging
import uuid
from typing import Sequence

from app.core.exceptions import NotFoundError
from app.models.risk_assessment import RiskAssessment
from app.models.sigma_detection import SigmaDetection
from app.repositories.parsed_log_repository import ParsedLogRepository
from app.repositories.risk_repository import RiskRepository
from app.repositories.sigma_detection_repository import SigmaDetectionRepository
from app.risk.engine import RiskEngine
from app.schemas.risk import (
    BatchRiskAssessmentOut,
    RiskAssessmentOut,
    RiskExplanationOut,
    RiskFactorOut,
    RiskStatisticsOut,
)
from app.utils.datetime_utils import utc_now

logger = logging.getLogger(__name__)


class RiskService:
    def __init__(
        self,
        risk_repository: RiskRepository,
        sigma_detection_repository: SigmaDetectionRepository,
        parsed_log_repository: ParsedLogRepository,
    ):
        self.risk_repository = risk_repository
        self.sigma_detection_repository = sigma_detection_repository
        self.parsed_log_repository = parsed_log_repository

    def assess_detection(self, detection_id: uuid.UUID) -> RiskAssessmentOut:
        detection = self.sigma_detection_repository.get_by_id(detection_id)
        if not detection:
            raise NotFoundError(f"Sigma detection '{detection_id}' not found.")

        parsed_log = self.parsed_log_repository.get_by_id(detection.parsed_log_id)
        username = parsed_log.username if parsed_log else None
        hostname = parsed_log.hostname if parsed_log else None
        matched_count = len(detection.matched_fields or [])

        eval_result = RiskEngine.evaluate(
            severity=detection.severity,
            confidence=detection.confidence,
            mitre_tactics=detection.rule_tags or [],
            username=username,
            hostname=hostname,
            matched_fields_count=matched_count,
        )

        # Check if assessment already exists for this detection
        existing = self.risk_repository.get_by_detection_id(detection_id)
        if existing:
            existing.risk_score = eval_result["risk_score"]
            existing.risk_level = eval_result["risk_level"]
            existing.confidence = eval_result["confidence"]
            existing.calculated_at = utc_now()
            self.risk_repository.session.commit()
            assessment = existing
        else:
            assessment = RiskAssessment(
                id=uuid.uuid4(),
                sigma_detection_id=detection.id,
                risk_score=eval_result["risk_score"],
                risk_level=eval_result["risk_level"],
                confidence=eval_result["confidence"],
                calculated_at=utc_now(),
            )
            self.risk_repository.session.add(assessment)
            self.risk_repository.session.commit()

        factors = [
            RiskFactorOut(name=f["name"], impact=float(f["impact"]), detail=f["detail"])
            for f in eval_result["contributing_factors"]
        ]

        return RiskAssessmentOut(
            id=assessment.id,
            sigma_detection_id=assessment.sigma_detection_id,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            confidence=assessment.confidence,
            calculated_at=assessment.calculated_at,
            explanation=eval_result["explanation"],
            contributing_factors=factors,
        )

    def assess_all_unassessed(self) -> BatchRiskAssessmentOut:
        detections, _ = self.sigma_detection_repository.search(limit=10_000)
        assessed_count = 0
        by_level: dict[str, int] = {}
        total_score = 0.0

        for det in detections:
            existing = self.risk_repository.get_by_detection_id(det.id)
            if not existing:
                res = self.assess_detection(det.id)
                assessed_count += 1
                lvl_val = res.risk_level.value
                by_level[lvl_val] = by_level.get(lvl_val, 0) + 1
                total_score += res.risk_score

        avg_score = round(total_score / assessed_count, 1) if assessed_count > 0 else 0.0
        return BatchRiskAssessmentOut(
            assessed_count=assessed_count,
            by_level=by_level,
            average_score=avg_score,
        )

    def list_assessments(
        self,
        risk_level: Any = None,
        skip: int = 0,
        limit: int = 50,
    ) -> tuple[list[RiskAssessmentOut], int]:
        assessments, total = self.risk_repository.list_assessments(
            risk_level=risk_level, skip=skip, limit=limit
        )
        results: list[RiskAssessmentOut] = []
        for a in assessments:
            results.append(
                RiskAssessmentOut(
                    id=a.id,
                    sigma_detection_id=a.sigma_detection_id,
                    risk_score=a.risk_score,
                    risk_level=a.risk_level,
                    confidence=a.confidence,
                    calculated_at=a.calculated_at,
                    explanation=f"Calculated risk: {a.risk_level.value.upper()} ({a.risk_score}/100)",
                )
            )
        return results, total

    def get_statistics(self) -> RiskStatisticsOut:
        stats = self.risk_repository.get_statistics()
        return RiskStatisticsOut(**stats)

    def explain_risk(self, assessment_id: uuid.UUID) -> RiskExplanationOut:
        """Provide detailed, mathematical, transparent explanation of how risk was scored."""
        assessment = self.risk_repository.get_by_id(assessment_id)
        if not assessment:
            raise NotFoundError(f"Risk assessment '{assessment_id}' not found.")

        detection_id = assessment.sigma_detection_id
        detection = self.sigma_detection_repository.get_by_id(detection_id) if detection_id else None

        parsed_log = self.parsed_log_repository.get_by_id(detection.parsed_log_id) if detection else None
        username = parsed_log.username if parsed_log else None
        hostname = parsed_log.hostname if parsed_log else None
        matched_count = len(detection.matched_fields or []) if detection else 0

        if detection:
            eval_result = RiskEngine.evaluate(
                severity=detection.severity,
                confidence=detection.confidence,
                mitre_tactics=detection.rule_tags or [],
                username=username,
                hostname=hostname,
                matched_fields_count=matched_count,
            )
            factors = [
                RiskFactorOut(name=f["name"], impact=float(f["impact"]), detail=f["detail"])
                for f in eval_result["contributing_factors"]
            ]
            explanation = eval_result["explanation"]
            base_score = float(eval_result.get("base_severity_score", 40.0))
            formula = "Final Score = (Base Severity + Σ Tactic Weights) × Confidence Multiplier + Asset Weight"
        else:
            factors = [
                RiskFactorOut(
                    name="Direct Asset Finding",
                    impact=assessment.risk_score,
                    detail=f"Risk level {assessment.risk_level.value.upper()}",
                )
            ]
            explanation = f"Defensive web security finding risk assessment evaluated at {assessment.risk_score}."
            base_score = assessment.risk_score
            formula = "Web Security Finding Severity Model"

        return RiskExplanationOut(
            assessment_id=assessment.id,
            detection_id=detection_id,
            risk_score=assessment.risk_score,
            risk_level=assessment.risk_level,
            confidence=assessment.confidence,
            base_severity_score=base_score,
            environmental_multiplier=1.0,
            threat_intel_factor=0.0,
            calculation_formula=formula,
            explanation=explanation,
            contributing_factors=factors,
        )

