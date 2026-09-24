"""Integration tests for IOC extraction, querying, and statistics."""

import unittest
from app.database.session import SessionLocal
from app.repositories.ioc_repository import IOCRepository
from app.services.ioc_service import IOCService


class TestIOCPipeline(unittest.TestCase):
    def setUp(self):
        self.session = SessionLocal()
        self.ioc_repo = IOCRepository(self.session)
        self.ioc_service = IOCService(self.ioc_repo)

    def tearDown(self):
        self.session.close()

    def test_extract_and_register_from_text(self):
        sample_log = (
            "Suspicious connection from 198.51.100.42 to malicious-c2-domain.org. "
            "Downloaded payload with hash 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8."
        )
        extracted = self.ioc_service.extract_and_register_from_text(
            sample_log,
            source="SYSLOG",
            confidence=0.95,
            tags=["c2", "malware"],
        )
        self.assertGreaterEqual(len(extracted), 2)

        # Query statistics
        stats = self.ioc_service.get_statistics()
        self.assertGreaterEqual(stats["total_iocs"], 1)
        self.assertIn("ipv4", stats["by_type"])

        # Search
        results, total = self.ioc_service.list_iocs(search="198.51.100.42")
        self.assertGreaterEqual(total, 1)
        self.assertEqual(results[0].value, "198.51.100.42")
