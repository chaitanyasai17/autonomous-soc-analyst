"""Unit tests for the Deterministic Risk Engine."""

import unittest
from app.models.enums import RiskLevel
from app.risk.engine import RiskEngine


class TestRiskEngine(unittest.TestCase):
    def test_critical_risk_scoring(self):
        res = RiskEngine.evaluate(
            severity=RiskLevel.CRITICAL,
            confidence=0.95,
            mitre_tactics=["impact", "command_and_control"],
            username="admin",
            hostname="DC-01",
            matched_fields_count=3,
        )
        score = res["risk_score"]
        self.assertGreaterEqual(score, 75.0)
        self.assertLessEqual(score, 100.0)
        self.assertEqual(res["risk_level"], RiskLevel.CRITICAL)
        self.assertGreater(len(res["contributing_factors"]), 0)
        self.assertIn("explanation", res)

    def test_low_risk_scoring(self):
        res = RiskEngine.evaluate(
            severity=RiskLevel.LOW,
            confidence=0.5,
            mitre_tactics=[],
            username="testuser",
            hostname="PC-12",
            matched_fields_count=1,
        )
        score = res["risk_score"]
        self.assertLess(score, 50.0)
        self.assertEqual(res["risk_level"], RiskLevel.LOW)

    def test_score_bounded_between_zero_and_hundred(self):
        # Maximum possible scenario
        res_max = RiskEngine.evaluate(
            severity=RiskLevel.CRITICAL,
            confidence=1.0,
            mitre_tactics=["impact", "exfiltration", "credential_access", "privilege_escalation"],
            username="root",
            matched_fields_count=10,
        )
        self.assertLessEqual(res_max["risk_score"], 100.0)

        # Minimum possible scenario
        res_min = RiskEngine.evaluate(
            severity=RiskLevel.LOW,
            confidence=0.0,
            mitre_tactics=[],
            username="nobody",
            matched_fields_count=0,
        )
        self.assertGreaterEqual(res_min["risk_score"], 0.0)


if __name__ == "__main__":
    unittest.main()
