"""Web Security Posture scoring service — deterministic, mathematical security posture calculations."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Sequence

from app.models.enums import RiskLevel
from app.models.web_security_finding import WebSecurityFinding

logger = logging.getLogger(__name__)

CATEGORY_WEIGHTS: Dict[str, float] = {
    "Security Headers": 25.0,
    "TLS/Transport": 20.0,
    "Cookie Security": 15.0,
    "CORS Configuration": 15.0,
    "Information Disclosure": 15.0,
    "Input Validation": 10.0,
}

SEVERITY_DEDUCTIONS: Dict[RiskLevel, float] = {
    RiskLevel.CRITICAL: 10.0,
    RiskLevel.HIGH: 6.0,
    RiskLevel.MEDIUM: 3.0,
    RiskLevel.LOW: 1.0,
}


class WebSecurityPostureService:
    """Computes deterministic security posture scores based on empirical scan findings."""

    @staticmethod
    def calculate_scan_posture(findings: Sequence[WebSecurityFinding | Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate category breakdown and overall posture score (0.0 - 100.0).
        """
        # Initialize category points with maximum possible weights
        category_scores: Dict[str, float] = dict(CATEGORY_WEIGHTS)

        for finding in findings:
            cat = getattr(finding, "category", None) or finding.get("category", "")
            sev = getattr(finding, "severity", None) or finding.get("severity", RiskLevel.LOW)
            if isinstance(sev, str):
                try:
                    sev = RiskLevel(sev.lower())
                except ValueError:
                    sev = RiskLevel.LOW

            # Normalize category matching
            matched_cat = None
            for known_cat in CATEGORY_WEIGHTS.keys():
                if known_cat.lower() in cat.lower() or cat.lower() in known_cat.lower():
                    matched_cat = known_cat
                    break

            if not matched_cat:
                matched_cat = "Information Disclosure"

            deduction = SEVERITY_DEDUCTIONS.get(sev, 1.0)
            category_scores[matched_cat] = max(0.0, category_scores[matched_cat] - deduction)

        total_score = sum(category_scores.values())
        total_score = round(max(0.0, min(100.0, total_score)), 1)

        rating = "EXCELLENT"
        if total_score < 40.0:
            rating = "CRITICAL"
        elif total_score < 60.0:
            rating = "POOR"
        elif total_score < 75.0:
            rating = "FAIR"
        elif total_score < 90.0:
            rating = "GOOD"

        breakdown = {k: round(v, 1) for k, v in category_scores.items()}

        return {
            "posture_score": total_score,
            "posture_rating": rating,
            "breakdown": breakdown,
        }
