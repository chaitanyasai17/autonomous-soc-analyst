"""Unit tests for WebSecurityPostureService deterministic scoring."""

import unittest
from app.models.enums import RiskLevel
from app.services.web_security_posture_service import (
    CATEGORY_WEIGHTS,
    WebSecurityPostureService,
)


class TestWebSecurityPostureService(unittest.TestCase):
    def test_perfect_score_when_no_findings(self):
        result = WebSecurityPostureService.calculate_scan_posture([])
        self.assertEqual(result["posture_score"], 100.0)
        self.assertEqual(result["posture_rating"], "EXCELLENT")
        self.assertEqual(result["breakdown"]["Security Headers"], 25.0)

    def test_deductions_applied_correctly(self):
        findings = [
            {
                "category": "Security Headers",
                "severity": RiskLevel.HIGH,  # -6.0
            },
            {
                "category": "Security Headers",
                "severity": RiskLevel.MEDIUM,  # -3.0
            },
            {
                "category": "TLS/Transport",
                "severity": RiskLevel.CRITICAL,  # -10.0
            },
        ]
        result = WebSecurityPostureService.calculate_scan_posture(findings)
        # Headers: 25 - 6 - 3 = 16
        self.assertEqual(result["breakdown"]["Security Headers"], 16.0)
        # TLS: 20 - 10 = 10
        self.assertEqual(result["breakdown"]["TLS/Transport"], 10.0)
        # Total deduction = 19.0 -> 100 - 19 = 81.0
        self.assertEqual(result["posture_score"], 81.0)
        self.assertEqual(result["posture_rating"], "GOOD")

    def test_category_cannot_be_negative(self):
        findings = [
            {"category": "Cookie Security", "severity": RiskLevel.CRITICAL}
            for _ in range(5)  # 5 * -10 = -50, weight is 15
        ]
        result = WebSecurityPostureService.calculate_scan_posture(findings)
        self.assertEqual(result["breakdown"]["Cookie Security"], 0.0)
        self.assertGreaterEqual(result["posture_score"], 0.0)
