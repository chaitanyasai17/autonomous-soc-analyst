"""Integration tests for the Incident Lifecycle, Auto-Correlation, and State Transitions."""

import unittest
import uuid
from app.database.session import SessionLocal
from app.models.enums import IncidentStatus, RiskLevel
from app.repositories.incident_repository import IncidentRepository
from app.repositories.alert_repository import AlertRepository
from app.repositories.user_repository import UserRepository
from app.services.incident_service import IncidentService
from app.schemas.incident import IncidentCreate
from app.core.exceptions import ValidationFailedError


class TestIncidentLifecycle(unittest.TestCase):
    def setUp(self):
        self.session = SessionLocal()
        self.incident_repo = IncidentRepository(self.session)
        self.alert_repo = AlertRepository(self.session)
        self.user_repo = UserRepository(self.session)
        self.incident_service = IncidentService(
            self.incident_repo, self.alert_repo, self.user_repo, None
        )

    def tearDown(self):
        self.session.close()

    def test_incident_creation_and_sequencing(self):
        created = self.incident_service.create_incident(
            IncidentCreate(priority=RiskLevel.HIGH)
        )
        self.assertIsNotNone(created.id)
        self.assertTrue(created.incident_number.startswith("INC-"))
        self.assertEqual(created.status, IncidentStatus.OPEN)

    def test_lifecycle_transitions(self):
        created = self.incident_service.create_incident(
            IncidentCreate(priority=RiskLevel.CRITICAL)
        )
        # OPEN -> INVESTIGATING
        step1 = self.incident_service.update_status(created.id, IncidentStatus.INVESTIGATING)
        self.assertEqual(step1.status, IncidentStatus.INVESTIGATING)

        # INVESTIGATING -> CONTAINED
        step2 = self.incident_service.update_status(created.id, IncidentStatus.CONTAINED)
        self.assertEqual(step2.status, IncidentStatus.CONTAINED)

        # CONTAINED -> RESOLVED
        step3 = self.incident_service.update_status(created.id, IncidentStatus.RESOLVED)
        self.assertEqual(step3.status, IncidentStatus.RESOLVED)
        self.assertIsNotNone(step3.closed_at)

        # RESOLVED -> CLOSED
        step4 = self.incident_service.update_status(created.id, IncidentStatus.CLOSED)
        self.assertEqual(step4.status, IncidentStatus.CLOSED)

    def test_invalid_lifecycle_transition_rejected(self):
        created = self.incident_service.create_incident(
            IncidentCreate(priority=RiskLevel.LOW)
        )
        # Cannot jump from OPEN directly to RESOLVED without investigation and containment
        with self.assertRaises(ValidationFailedError):
            self.incident_service.update_status(created.id, IncidentStatus.RESOLVED)


if __name__ == "__main__":
    unittest.main()
