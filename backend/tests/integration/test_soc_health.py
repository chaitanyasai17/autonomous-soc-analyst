"""Integration tests for SOC Health Diagnostics (all 13 engines)."""

import unittest
from app.database.session import SessionLocal
from app.dependencies.services import get_detection_engine
from app.services.soc_health_service import SOCHealthService


class TestSOCHealth(unittest.TestCase):
    def setUp(self):
        self.session = SessionLocal()
        self.detection_engine = get_detection_engine()
        self.health_service = SOCHealthService(db=self.session, detection_engine=self.detection_engine)

    def tearDown(self):
        self.session.close()

    def test_all_13_engines_diagnosed(self):
        report = self.health_service.check_all_components()
        self.assertEqual(report.total_components, 13)
        self.assertIn(report.overall_status, ("HEALTHY", "DEGRADED"))

        expected_engines = [
            "database",
            "log_ingestion",
            "log_parser",
            "sigma_detection",
            "mitre_attack",
            "risk_assessment",
            "alert_manager",
            "alert_correlation",
            "incident_manager",
            "ai_threat_analyst",
            "attack_simulator",
            "notification_engine",
            "web_security_scanner",
        ]
        for eng in expected_engines:
            self.assertIn(eng, report.components)
            comp = report.components[eng]
            self.assertIn(comp.status, ("HEALTHY", "DEGRADED"))
            self.assertGreaterEqual(comp.latency_ms, 0.0)
            self.assertTrue(len(comp.message) > 0)
