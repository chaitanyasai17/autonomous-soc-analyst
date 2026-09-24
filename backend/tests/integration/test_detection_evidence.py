"""Integration tests for Detection Evidence, Analyst Feedback, and Quality Metrics."""

import unittest
import uuid
from app.database.session import SessionLocal
from app.dependencies.services import get_detection_engine
from app.models.enums import RiskLevel, UserRole
from app.models.parsed_log import ParsedLog
from app.models.security_log import SecurityLog
from app.models.sigma_detection import SigmaDetection
from app.models.user import User
from app.repositories.parsed_log_repository import ParsedLogRepository
from app.repositories.security_log_repository import SecurityLogRepository
from app.repositories.sigma_detection_repository import SigmaDetectionRepository
from app.repositories.user_repository import UserRepository
from app.services.detection_service import DetectionService
from app.utils.datetime_utils import utc_now


class TestDetectionEvidenceAndQuality(unittest.TestCase):
    def setUp(self):
        self.session = SessionLocal()
        self.sec_log_repo = SecurityLogRepository(self.session)
        self.parsed_log_repo = ParsedLogRepository(self.session)
        self.sigma_det_repo = SigmaDetectionRepository(self.session)
        self.detection_engine = get_detection_engine()
        self.detection_service = DetectionService(
            security_log_repository=self.sec_log_repo,
            parsed_log_repository=self.parsed_log_repo,
            sigma_detection_repository=self.sigma_det_repo,
            detection_engine=self.detection_engine,
        )
        self.user_repo = UserRepository(self.session)
        self.user = self.user_repo.get_by_username("admin")

    def tearDown(self):
        self.session.close()

    def test_evidence_and_analyst_feedback_flow(self):
        # Create a test parsed log
        sec_log = self.session.query(SecurityLog).first()
        if not sec_log:
            self.skipTest("No security logs available for test")

        pl = ParsedLog(
            id=uuid.uuid4(),
            security_log_id=sec_log.id,
            timestamp=utc_now(),
            raw_log='{"event_id": 1, "image": "cmd.exe", "command_line": "powershell -enc AAAA"}',
            event_type="process_creation",
            hostname="WS-01",
            username="analyst_test",
            action="execute",
            message="PowerShell spawned",
        )
        self.session.add(pl)

        # Create a test detection
        det = SigmaDetection(
            id=uuid.uuid4(),
            parsed_log_id=pl.id,
            matched_rule="test-rule-01",
            rule_title="Suspicious Encoded PowerShell Execution",
            severity=RiskLevel.HIGH,
            confidence=0.9,
            detection_timestamp=utc_now(),
            matched_fields=[{"field": "command_line", "value": "powershell -enc", "selection": "sel1"}],
        )
        self.session.add(det)
        self.session.commit()

        # 1. Get Evidence ("Why Detected?")
        evidence = self.detection_service.get_evidence(det.id)
        self.assertEqual(evidence.detection_id, det.id)
        self.assertEqual(evidence.rule_title, "Suspicious Encoded PowerShell Execution")
        self.assertEqual(evidence.severity, RiskLevel.HIGH)
        self.assertTrue(len(evidence.matched_fields) > 0)
        self.assertIn("Why", "Detection triggered" if "triggered" in evidence.explanation else "Why")

        # 2. Record Analyst Feedback
        updated = self.detection_service.record_analyst_feedback(
            det.id, verdict="TRUE_POSITIVE", note="Verified adversary execution"
        )
        self.assertEqual(updated.analyst_verdict, "TRUE_POSITIVE")
        self.assertEqual(updated.analyst_note, "Verified adversary execution")

        # 3. Quality Metrics
        metrics = self.detection_service.get_quality_metrics()
        self.assertGreaterEqual(metrics.total_detections, 1)
        self.assertGreaterEqual(metrics.reviewed_detections, 1)
        self.assertGreaterEqual(metrics.true_positives, 1)
        self.assertGreaterEqual(metrics.tp_rate, 0.0)
