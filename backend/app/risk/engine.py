"""
Deterministic, explainable Risk Scoring Engine for security detections.
Combines rule severity, detection confidence, MITRE ATT&CK tactic weights,
and asset/telemetry factors into an interpretable 0–100 score.
"""

from __future__ import annotations

from typing import Any, Dict, List

from app.models.enums import RiskLevel

# Base score contribution by rule severity
SEVERITY_BASE_SCORES: Dict[str, float] = {
    RiskLevel.CRITICAL.value: 85.0,
    RiskLevel.HIGH.value: 65.0,
    RiskLevel.MEDIUM.value: 40.0,
    RiskLevel.LOW.value: 15.0,
}

# Additive risk based on MITRE tactic severity
TACTIC_RISK_WEIGHTS: Dict[str, float] = {
    "impact": 15.0,
    "exfiltration": 12.0,
    "command_and_control": 10.0,
    "credential_access": 10.0,
    "privilege_escalation": 8.0,
    "persistence": 7.0,
    "defense_evasion": 6.0,
    "execution": 6.0,
    "initial_access": 5.0,
    "lateral_movement": 8.0,
    "discovery": 4.0,
    "collection": 5.0,
}

PRIVILEGED_USERS = {"root", "admin", "administrator", "system", "nt authority\\system"}


class RiskEngine:
    """Calculates deterministic composite risk score and transparent breakdown."""

    @classmethod
    def evaluate(
        cls,
        severity: RiskLevel | str,
        confidence: float,
        mitre_tactics: List[str] | None = None,
        username: str | None = None,
        hostname: str | None = None,
        matched_fields_count: int = 0,
    ) -> Dict[str, Any]:
        sev_str = severity.value if isinstance(severity, RiskLevel) else str(severity).lower()
        base_score = SEVERITY_BASE_SCORES.get(sev_str, 40.0)

        factors: List[Dict[str, Any]] = [
            {
                "name": "Base Rule Severity",
                "impact": base_score,
                "detail": f"Derived from Sigma rule severity '{sev_str.upper()}'.",
            }
        ]

        # Confidence modifier (weights between 0.7x and 1.0x)
        conf_clamped = max(0.1, min(1.0, confidence))
        confidence_factor = (conf_clamped - 0.7) * 15.0
        factors.append(
            {
                "name": "Detection Confidence",
                "impact": round(confidence_factor, 1),
                "detail": f"Evaluator confidence score: {conf_clamped:.2f}.",
            }
        )

        # MITRE tactic weight
        tactics_adjustment = 0.0
        identified_tactics = mitre_tactics or []
        for tac in identified_tactics:
            tac_clean = tac.lower().replace("attack.", "").strip()
            weight = TACTIC_RISK_WEIGHTS.get(tac_clean, 3.0)
            tactics_adjustment += weight

        tactics_adjustment = min(tactics_adjustment, 20.0)
        if identified_tactics:
            factors.append(
                {
                    "name": "MITRE ATT&CK Criticality",
                    "impact": round(tactics_adjustment, 1),
                    "detail": f"Weighted based on tactics: {', '.join(identified_tactics)}.",
                }
            )

        # Telemetry & Asset sensitivity
        asset_adjustment = 0.0
        if username and username.lower().strip() in PRIVILEGED_USERS:
            asset_adjustment += 10.0
            factors.append(
                {
                    "name": "Privileged Account Target",
                    "impact": 10.0,
                    "detail": f"Target username '{username}' holds elevated administrative privileges.",
                }
            )

        if matched_fields_count > 2:
            asset_adjustment += 5.0
            factors.append(
                {
                    "name": "High Signature Density",
                    "impact": 5.0,
                    "detail": f"Event matched {matched_fields_count} suspicious field selections.",
                }
            )

        # Composite score calculation
        raw_score = base_score + confidence_factor + tactics_adjustment + asset_adjustment
        final_score = round(max(0.0, min(100.0, raw_score)), 1)

        # Determine level
        if final_score >= 85.0:
            level = RiskLevel.CRITICAL
        elif final_score >= 60.0:
            level = RiskLevel.HIGH
        elif final_score >= 30.0:
            level = RiskLevel.MEDIUM
        else:
            level = RiskLevel.LOW

        explanation = (
            f"Overall risk evaluated as {level.value.upper()} ({final_score}/100). "
            f"Base severity contributes {base_score} pts, detection confidence applies {round(confidence_factor, 1)} pts, "
            f"MITRE tactics add {round(tactics_adjustment, 1)} pts, and asset context adds {round(asset_adjustment, 1)} pts."
        )

        return {
            "risk_score": final_score,
            "risk_level": level,
            "confidence": conf_clamped,
            "explanation": explanation,
            "contributing_factors": factors,
        }
