"""Integration tests for FastAPI REST API endpoints using TestClient."""

import unittest
from fastapi.testclient import TestClient
from app.main import app


class TestAPIEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        # Authenticate as super admin
        login_resp = cls.client.post(
            "/api/v1/auth/login",
            data={"username": "admin", "password": "Admin1234!"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if login_resp.status_code == 200:
            token = login_resp.json()["access_token"]
            cls.auth_headers = {"Authorization": f"Bearer {token}"}
        else:
            cls.auth_headers = {}

    def test_health_check_endpoint(self):
        resp = self.client.get("/api/v1/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("success", False))

    def test_current_user_me(self):
        resp = self.client.get("/api/v1/auth/me", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()["data"]
        self.assertEqual(data["username"], "admin")
        self.assertEqual(data["role"], "super_admin")

    def test_list_alerts(self):
        resp = self.client.get("/api/v1/alerts", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("data", data)
        self.assertIn("total", data)

    def test_list_incidents(self):
        resp = self.client.get("/api/v1/incidents", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("data", data)

    def test_ai_status(self):
        resp = self.client.get("/api/v1/ai/status", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()["data"]
        self.assertIn("provider", data)

    def test_mitre_matrix(self):
        resp = self.client.get("/api/v1/mitre/matrix", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()["data"]
        self.assertIn("tactics", data)

    def test_dashboard_summary(self):
        resp = self.client.get("/api/v1/dashboard/summary", headers=self.auth_headers)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()["data"]
        self.assertIn("total_alerts", data)


if __name__ == "__main__":
    unittest.main()
