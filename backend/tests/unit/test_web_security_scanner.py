"""Unit tests for WebSecurityScanner safety controls and allowlist boundaries."""

import unittest
from app.core.exceptions import PermissionDeniedError
from app.services.web_security_scanner import WebSecurityScanner


class TestWebSecurityScannerSafety(unittest.TestCase):
    def test_localhost_and_loopback_allowed(self):
        scanner = WebSecurityScanner("http://localhost:8000")
        self.assertTrue(scanner.validate_target_authorization())
        self.assertIn(scanner.resolved_ip, ("127.0.0.1", "::1"))

        scanner2 = WebSecurityScanner("http://127.0.0.1:5173")
        self.assertTrue(scanner2.validate_target_authorization())
        self.assertEqual(scanner2.resolved_ip, "127.0.0.1")

    def test_bare_ip_and_port_normalization(self):
        scanner = WebSecurityScanner("127.0.0.1")
        self.assertEqual(scanner.target_host, "127.0.0.1")
        self.assertEqual(scanner.target_port, 80)
        self.assertTrue(scanner.validate_target_authorization())

        scanner_port = WebSecurityScanner("127.0.0.1:8000")
        self.assertEqual(scanner_port.target_host, "127.0.0.1")
        self.assertEqual(scanner_port.target_port, 8000)
        self.assertTrue(scanner_port.validate_target_authorization())

    def test_unauthorized_external_host_rejected(self):
        scanner = WebSecurityScanner("https://evil-unauthorized-target.com")
        with self.assertRaises(PermissionDeniedError):
            scanner.validate_target_authorization()

    def test_custom_allowlist_entry_accepted(self):
        scanner = WebSecurityScanner("https://api.partner.internal", custom_allowlist=["api.partner.internal"])
        self.assertTrue(scanner.validate_target_authorization())

    def test_service_exposure_check_format(self):
        scanner = WebSecurityScanner("127.0.0.1:8000")
        scanner.validate_target_authorization()
        exposed, findings = scanner._check_service_exposure()
        self.assertIsInstance(exposed, list)
        self.assertIsInstance(findings, list)
        if exposed:
            first = exposed[0]
            self.assertIn("port", first)
            self.assertIn("service", first)
            self.assertEqual(first["state"], "open")
