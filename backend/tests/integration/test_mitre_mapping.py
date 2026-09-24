"""Integration tests for the MITRE ATT&CK catalog and technique mapping."""

import unittest
from app.database.session import SessionLocal
from app.repositories.mitre_repository import MitreRepository
from app.services.mitre_service import MitreService


class TestMitreMapping(unittest.TestCase):
    def setUp(self):
        self.session = SessionLocal()
        self.mitre_repo = MitreRepository(self.session)
        self.mitre_service = MitreService(self.mitre_repo)

    def tearDown(self):
        self.session.close()

    def test_mitre_tactics_seeded(self):
        tactics = self.mitre_service.get_tactics()
        self.assertGreaterEqual(len(tactics), 10)
        tactic_names = [t.name.lower() for t in tactics]
        self.assertTrue(any("execution" in n for n in tactic_names))
        self.assertTrue(any("persistence" in n for n in tactic_names))

    def test_mitre_matrix_structure(self):
        matrix = self.mitre_service.get_matrix()
        self.assertGreater(matrix.total_tactics, 0)
        self.assertGreater(matrix.total_techniques, 0)
        self.assertGreaterEqual(len(matrix.tactics), 10)

    def test_search_technique_by_id(self):
        tech = self.mitre_service.get_technique("T1059")
        self.assertIsNotNone(tech)
        self.assertEqual(tech.technique_id, "T1059")
        self.assertIn("command", tech.technique_name.lower())


if __name__ == "__main__":
    unittest.main()
