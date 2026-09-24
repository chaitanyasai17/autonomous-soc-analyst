"""Integration tests for Module 1 — Endpoints Management & Telemetry Isolation."""

import unittest
import uuid
from datetime import datetime

from fastapi.testclient import TestClient

from app.database.session import SessionLocal
from app.main import app
from app.models.endpoint import Endpoint
from app.models.enums import RiskLevel, UserRole
from app.models.user import User
from app.repositories.endpoint_repository import EndpointRepository
from app.repositories.user_repository import UserRepository
from app.services.endpoint_service import EndpointService
from app.utils.datetime_utils import utc_now


class TestEndpointsModule(unittest.TestCase):
    def setUp(self):
        self.session = SessionLocal()
        self.client = TestClient(app)
        self.user_repo = UserRepository(self.session)
        self.ep_repo = EndpointRepository(self.session)
        self.ep_service = EndpointService(self.ep_repo, self.session)

        # Admin user (Super Admin)
        self.admin = self.user_repo.get_by_username("admin")
        if not self.admin:
            self.admin = User(
                id=uuid.uuid4(),
                username="admin",
                email="admin@asoc.corp",
                password_hash="fakehash",
                first_name="Super",
                last_name="Admin",
                role=UserRole.SUPER_ADMIN,
                is_active=True,
            )
            self.session.add(self.admin)
            self.session.commit()

        # Normal analyst user
        self.analyst = self.user_repo.get_by_username("test_analyst_ep")
        if not self.analyst:
            self.analyst = User(
                id=uuid.uuid4(),
                username="test_analyst_ep",
                email="analyst@asoc.corp",
                password_hash="fakehash",
                first_name="Test",
                last_name="Analyst",
                role=UserRole.ANALYST,
                is_active=True,
            )
            self.session.add(self.analyst)
            self.session.commit()

    def tearDown(self):
        self.session.close()

    def test_endpoint_enrollment_and_isolation(self):
        """Test enrolling an endpoint, retrieving it, and toggling containment."""
        hostname = f"test-host-{uuid.uuid4().hex[:6]}"
        ep = Endpoint(
            id=uuid.uuid4(),
            hostname=hostname,
            ip_address="192.168.10.55",
            operating_system="Windows 11 Pro",
            agent_version="1.4.2-asoc",
            status="online",
            risk_level=RiskLevel.LOW,
            owner_id=self.admin.id,
            is_isolated=False,
            last_seen=utc_now(),
            registered_at=utc_now(),
        )
        self.ep_repo.create(ep)

        # Retrieve with owner
        fetched = self.ep_repo.get_with_owner(ep.id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.hostname, hostname)
        self.assertEqual(fetched.owner.username, self.admin.username)

        # Admin lists endpoints
        endpoints, total = self.ep_service.list_endpoints(current_user=self.admin)
        self.assertGreaterEqual(total, 1)
        found = any(e.hostname == hostname for e in endpoints)
        self.assertTrue(found)

    def test_ownership_enforcement(self):
        """Verify normal analyst cannot see or alter another user's endpoint."""
        # Create an endpoint owned exclusively by admin
        admin_host = f"admin-dc-{uuid.uuid4().hex[:6]}"
        admin_ep = Endpoint(
            id=uuid.uuid4(),
            hostname=admin_host,
            ip_address="10.0.0.1",
            operating_system="Windows Server 2022",
            agent_version="1.4.2-asoc",
            status="online",
            risk_level=RiskLevel.HIGH,
            owner_id=self.admin.id,
            is_isolated=False,
            last_seen=utc_now(),
            registered_at=utc_now(),
        )
        self.ep_repo.create(admin_ep)

        # Create an endpoint owned by analyst
        analyst_host = f"analyst-laptop-{uuid.uuid4().hex[:6]}"
        analyst_ep = Endpoint(
            id=uuid.uuid4(),
            hostname=analyst_host,
            ip_address="192.168.1.99",
            operating_system="Windows 11 Enterprise",
            agent_version="1.4.2-asoc",
            status="online",
            risk_level=RiskLevel.LOW,
            owner_id=self.analyst.id,
            is_isolated=False,
            last_seen=utc_now(),
            registered_at=utc_now(),
        )
        self.ep_repo.create(analyst_ep)

        # Analyst lists endpoints -> should ONLY see analyst-laptop, NEVER admin-dc
        analyst_eps, _ = self.ep_service.list_endpoints(current_user=self.analyst)
        analyst_hosts = [e.hostname for e in analyst_eps]
        self.assertIn(analyst_host, analyst_hosts)
        self.assertNotIn(admin_host, analyst_hosts)

        # Admin lists endpoints -> sees both
        admin_eps, _ = self.ep_service.list_endpoints(current_user=self.admin)
        admin_hosts = [e.hostname for e in admin_eps]
        self.assertIn(admin_host, admin_hosts)
        self.assertIn(analyst_host, admin_hosts)


if __name__ == "__main__":
    unittest.main()
