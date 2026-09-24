"""Integration tests for the Web Security Lab pipeline and SOC Alert/Incident integration."""

import unittest
import uuid
from app.database.session import SessionLocal
from app.models.enums import RiskLevel, UserRole
from app.models.user import User
from app.repositories.alert_repository import AlertRepository
from app.repositories.incident_repository import IncidentRepository
from app.repositories.ioc_repository import IOCRepository
from app.repositories.risk_repository import RiskRepository
from app.repositories.user_repository import UserRepository
from app.repositories.web_security_allowlist_repository import WebSecurityAllowlistRepository
from app.repositories.web_security_finding_repository import WebSecurityFindingRepository
from app.repositories.web_security_scan_repository import WebSecurityScanRepository
from app.schemas.web_security import AllowlistCreateRequest, ScanLaunchRequest
from app.services.incident_service import IncidentService
from app.services.ioc_service import IOCService
from app.services.web_security_posture_service import WebSecurityPostureService
from app.services.web_security_service import WebSecurityService


class TestWebSecurityPipeline(unittest.TestCase):
    def setUp(self):
        self.session = SessionLocal()
        self.scan_repo = WebSecurityScanRepository(self.session)
        self.finding_repo = WebSecurityFindingRepository(self.session)
        self.allowlist_repo = WebSecurityAllowlistRepository(self.session)
        self.posture_service = WebSecurityPostureService()
        self.alert_repo = AlertRepository(self.session)
        self.risk_repo = RiskRepository(self.session)
        self.ioc_repo = IOCRepository(self.session)
        self.ioc_service = IOCService(self.ioc_repo)
        self.user_repo = UserRepository(self.session)
        self.incident_repo = IncidentRepository(self.session)
        self.incident_service = IncidentService(
            self.incident_repo, self.alert_repo, self.user_repo, None
        )
        self.web_security_service = WebSecurityService(
            scan_repo=self.scan_repo,
            finding_repo=self.finding_repo,
            allowlist_repo=self.allowlist_repo,
            posture_service=self.posture_service,
            alert_repo=self.alert_repo,
            risk_repo=self.risk_repo,
            ioc_service=self.ioc_service,
            incident_service=self.incident_service,
            notification_service=None,
        )

        # Test admin user
        self.admin = self.user_repo.get_by_username("admin")
        if not self.admin:
            self.admin = User(
                id=uuid.uuid4(),
                username="admin_test_ws",
                email="admin_test_ws@asoc.corp",
                password_hash="fakehash",
                first_name="Admin",
                last_name="Test",
                role=UserRole.SUPER_ADMIN,
                is_active=True,
            )
            self.session.add(self.admin)
            self.session.commit()

    def tearDown(self):
        self.session.close()

    def test_allowlist_crud(self):
        test_pattern = f"test-target-{uuid.uuid4().hex[:6]}.internal"
        req = AllowlistCreateRequest(pattern=test_pattern, description="Internal test target")
        entry = self.web_security_service.create_allowlist_entry(req, user=self.admin)
        self.assertEqual(entry.pattern, test_pattern)

        # Retrieve allowlist
        entries, total = self.web_security_service.list_allowlist()
        self.assertTrue(any(e.pattern == test_pattern for e in entries))

        # Delete entry
        self.web_security_service.delete_allowlist_entry(entry.id)

    def test_scan_and_alert_promotion_pipeline(self):
        # Scan localhost (standard profile)
        scan_req = ScanLaunchRequest(target_url="http://127.0.0.1:8000", scan_profile="standard", timeout_seconds=2)
        scan_out = self.web_security_service.launch_scan(scan_req, user=self.admin)
        self.assertEqual(scan_out.target_host, "127.0.0.1")
        self.assertIn(scan_out.status, ("completed", "running"))
        self.assertGreaterEqual(scan_out.posture_score, 0.0)

        # Findings should be registered
        findings, total = self.web_security_service.get_scan_findings(scan_out.id)
        self.assertGreaterEqual(total, 1)

        finding_to_promote = findings[0]
        # Promote finding to SOC Alert
        alert_out = self.web_security_service.promote_finding_to_alert(
            finding_to_promote.id, user=self.admin, auto_correlate=True
        )
        self.assertIsNotNone(alert_out.id)
        self.assertIn("Web Security:", alert_out.title)

        # Verify Alert is linked to Finding
        refreshed_finding = self.web_security_service.get_finding(finding_to_promote.id)
        self.assertEqual(refreshed_finding.related_alert_id, alert_out.id)

        # Verify IOC was registered
        iocs, _ = self.ioc_service.list_iocs(search="127.0.0.1")
        self.assertGreaterEqual(len(iocs), 1)

        # Verify scan record attributes
        self.assertEqual(scan_out.resolved_ip, "127.0.0.1")
        self.assertIsNotNone(scan_out.exposed_services)
        self.assertGreaterEqual(scan_out.informational_count, 0)

        # Verify Scan History and Statistics
        stats = self.web_security_service.get_scan_statistics()
        self.assertIn("total_scans", stats)
        history = self.web_security_service.get_scan_history(target_host="127.0.0.1")
        self.assertGreaterEqual(len(history), 1)

        # Verify Posture summary
        posture = self.web_security_service.get_posture_summary(target_host="127.0.0.1")
        self.assertEqual(posture.target_host, "127.0.0.1")
        self.assertIn("Security Headers", posture.breakdown)
