"""Integration tests for Audit Trail, Pipeline Traceability, and Global Search."""

import unittest
import uuid
from datetime import datetime

from fastapi.testclient import TestClient

from app.database.session import SessionLocal
from app.main import app
from app.models.alert import Alert
from app.models.enums import AlertStatus, IncidentStatus, LogSource, ProcessingStatus, RiskLevel
from app.models.incident import Incident
from app.models.ioc_record import IOCRecord
from app.models.parsed_log import ParsedLog
from app.models.risk_assessment import RiskAssessment
from app.models.security_log import SecurityLog
from app.models.sigma_detection import SigmaDetection
from app.models.user import User
from app.repositories.audit_log_repository import AuditLogRepository
from app.repositories.user_repository import UserRepository
from app.services.audit_service import AuditService
from app.services.global_search_service import GlobalSearchService
from app.services.pipeline_trace_service import PipelineTraceService


class TestAuditAndTracePipeline(unittest.TestCase):
    def setUp(self):
        self.session = SessionLocal()
        self.client = TestClient(app)
        self.audit_repo = AuditLogRepository(self.session)
        self.audit_service = AuditService(self.audit_repo)
        self.trace_service = PipelineTraceService(self.session)
        self.search_service = GlobalSearchService(self.session)
        self.user_repo = UserRepository(self.session)

        # Get or create admin user
        self.admin = self.user_repo.get_by_username("admin")
        if not self.admin:
            self.admin = User(
                id=uuid.uuid4(),
                username="admin",
                email="admin@asoc.corp",
                password_hash="fakehash",
                first_name="Super",
                last_name="Admin",
                role="super_admin",
                is_active=True,
            )
            self.session.add(self.admin)
            self.session.commit()

    def tearDown(self):
        self.session.close()

    def test_audit_log_recording_and_search(self):
        """Verify immutable audit records can be persisted and searched."""
        entry = self.audit_service.log(
            action="TEST_ACTION",
            user=self.admin,
            object_type="SYSTEM",
            object_id="SYS-100",
            details={"key": "test_value"},
        )
        self.assertIsNotNone(entry.id)
        self.assertEqual(entry.action, "TEST_ACTION")
        self.assertEqual(entry.username, self.admin.username)

        # Search for it
        items, total = self.audit_service.search(action="TEST_ACTION")
        self.assertGreaterEqual(total, 1)
        found = any(i.id == entry.id for i in items)
        self.assertTrue(found)

    def test_pipeline_trace_full_chain(self):
        """Verify complete backwards and forwards provenance graph generation."""
        # 1. SecurityLog
        sec_log = SecurityLog(
            id=uuid.uuid4(),
            filename="trace_test.csv",
            original_filename="trace_test.csv",
            log_source=LogSource.ENDPOINT,
            file_type="csv",
            uploaded_by_id=self.admin.id,
            upload_time=datetime.utcnow(),
            processing_status=ProcessingStatus.COMPLETED,
            file_size=1024,
            mime_type="text/csv",
            storage_path="trace_test.csv",
            checksum_sha256="fake_sha256_for_trace_test",
        )
        self.session.add(sec_log)
        self.session.flush()

        # 2. ParsedLog
        parsed_log = ParsedLog(
            id=uuid.uuid4(),
            security_log_id=sec_log.id,
            timestamp=datetime.utcnow(),
            event_type="authentication_failed",
            source_ip="192.168.100.50",
            destination_ip="10.0.0.1",
            username="test_target_user",
            hostname="server-dc-01",
            raw_log="Sample raw log for trace",
        )
        self.session.add(parsed_log)
        self.session.flush()

        # 3. SigmaDetection
        detection = SigmaDetection(
            id=uuid.uuid4(),
            parsed_log_id=parsed_log.id,
            matched_rule="rules/trace_test.yml",
            rule_title="Trace Verification Rule",
            severity=RiskLevel.HIGH,
            confidence=0.95,
            detection_timestamp=datetime.utcnow(),
            matched_fields=[{"field": "username", "value": "test_target_user"}],
            rule_tags=["attack.t1110"],
        )
        self.session.add(detection)
        self.session.flush()

        # 4. RiskAssessment
        risk = RiskAssessment(
            id=uuid.uuid4(),
            sigma_detection_id=detection.id,
            risk_score=85.0,
            risk_level=RiskLevel.HIGH,
            confidence=0.95,
            calculated_at=datetime.utcnow(),
        )
        self.session.add(risk)
        self.session.flush()

        # 5. Alert
        alert = Alert(
            id=uuid.uuid4(),
            risk_assessment_id=risk.id,
            title="Alert: Trace Verification Fired",
            description="Generated for trace verification test",
            severity=RiskLevel.HIGH,
            status=AlertStatus.OPEN,
        )
        self.session.add(alert)
        self.session.flush()

        # 6. Incident
        incident = Incident(
            id=uuid.uuid4(),
            incident_number=f"INC-2026-TRC{uuid.uuid4().hex[:4].upper()}",
            priority=RiskLevel.HIGH,
            status=IncidentStatus.INVESTIGATING,
            opened_at=datetime.utcnow(),
        )
        self.session.add(incident)
        self.session.flush()

        # Link alert to incident
        alert.incident_id = incident.id
        self.session.commit()

        # Execute trace on incident
        trace = self.trace_service.trace("incident", incident.id)
        self.assertEqual(trace["queried_type"], "incident")
        self.assertGreaterEqual(trace["stages_count"], 4)

        stages = [s["stage"] for s in trace["stages"]]
        self.assertIn("INGESTION", stages)
        self.assertIn("PARSING", stages)
        self.assertIn("DETECTION", stages)
        self.assertIn("ALERT", stages)
        self.assertIn("INCIDENT", stages)

        # Execute trace on alert
        alert_trace = self.trace_service.trace("alert", alert.id)
        self.assertGreaterEqual(alert_trace["stages_count"], 4)

        # Execute trace on detection
        det_trace = self.trace_service.trace("detection", detection.id)
        self.assertGreaterEqual(det_trace["stages_count"], 4)

    def test_global_search(self):
        """Verify cross-entity global intelligence search engine."""
        search_res = self.search_service.search("192.168", limit_per_type=5)
        self.assertEqual(search_res["query"], "192.168")
        self.assertIn("categories", search_res)
        self.assertIn("events", search_res["categories"])


if __name__ == "__main__":
    unittest.main()
