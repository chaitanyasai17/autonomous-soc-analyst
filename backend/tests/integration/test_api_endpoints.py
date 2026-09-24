import os
import secrets
import unittest
import uuid
from fastapi.testclient import TestClient
from app.main import app
from app.config import get_settings
from app.database.session import SessionLocal
from app.models.user import User
from app.models.enums import UserRole
from app.security.hashing import hash_password, verify_password


class TestAPIEndpoints(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)
        settings = get_settings()
        admin_username = settings.ADMIN_USERNAME or "admin"
        admin_password = settings.ADMIN_PASSWORD or os.environ.get("ADMIN_PASSWORD")
        
        # If no password provided in settings/env, use an ephemeral test credential
        if not admin_password:
            admin_password = secrets.token_urlsafe(24)

        # Ensure the test administrator user exists with this password hash
        with SessionLocal() as db:
            admin = db.query(User).filter_by(username=admin_username).first()
            if not admin:
                admin = User(
                    id=uuid.uuid4(),
                    username=admin_username,
                    email="admin@test.local",
                    first_name="SOC",
                    last_name="Administrator",
                    role=UserRole.SUPER_ADMIN,
                    password_hash=hash_password(admin_password),
                    is_active=True,
                )
                db.add(admin)
                db.commit()
            elif not verify_password(admin_password, admin.password_hash):
                admin.password_hash = hash_password(admin_password)
                db.commit()

        login_resp = cls.client.post(
            "/api/v1/auth/login",
            data={"username": admin_username, "password": admin_password},
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
