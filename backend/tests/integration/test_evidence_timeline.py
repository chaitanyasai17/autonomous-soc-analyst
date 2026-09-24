"""Integration tests for Module 3 — Evidence Timeline Service & API."""

import unittest
import uuid
from datetime import datetime

from fastapi.testclient import TestClient

from app.database.session import SessionLocal
from app.dependencies.auth import get_current_active_user
from app.main import app
from app.models.enums import UserRole
from app.models.user import User
from app.repositories.user_repository import UserRepository
from app.services.evidence_timeline_service import EvidenceTimelineService


class TestEvidenceTimelineModule(unittest.TestCase):
    def setUp(self):
        self.session = SessionLocal()
        self.client = TestClient(app)
        self.user_repo = UserRepository(self.session)
        self.timeline_service = EvidenceTimelineService(self.session)

        # Admin user
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

        # Override auth dependency
        app.dependency_overrides[get_current_active_user] = lambda: self.admin

    def tearDown(self):
        app.dependency_overrides.clear()
        self.session.close()

    def test_timeline_service_build(self):
        """Test that EvidenceTimelineService gathers timeline entries from database."""
        result = self.timeline_service.build_timeline(limit=50)
        self.assertIsNotNone(result)
        self.assertIsInstance(result.timeline, list)
        self.assertEqual(result.total_events, len(result.timeline))

        # Check entry attributes if there are events in DB
        if result.timeline:
            first = result.timeline[0]
            self.assertTrue(hasattr(first, "stage"))
            self.assertTrue(hasattr(first, "timestamp"))
            self.assertTrue(hasattr(first, "description"))
            self.assertTrue(hasattr(first, "object_id"))

    def test_timeline_api_endpoint(self):
        """Test GET /api/v1/timeline returns 200 and valid JSON schema."""
        response = self.client.get("/api/v1/timeline?limit=30")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertTrue(payload["success"])
        data = payload["data"]
        self.assertIn("total_events", data)
        self.assertIn("timeline", data)
        self.assertIsInstance(data["timeline"], list)


if __name__ == "__main__":
    unittest.main()
