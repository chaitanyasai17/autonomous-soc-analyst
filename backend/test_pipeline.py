"""
Autonomous SOC Analyst — Full Pipeline Verification Script.
"""

from fastapi.testclient import TestClient
from app.main import app

def run_pipeline():
    client = TestClient(app)

    # 1. Login
    login_res = client.post("/api/v1/auth/login", data={"username": "admin", "password": "Admin1234!"})
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token = login_res.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("1. Login: SUCCESS (JWT Token acquired)")

    # 2. Upload Log
    with open("../examples/sample-logs/suspicious_commands.csv", "rb") as f:
        upload_res = client.post(
            "/api/v1/logs/upload",
            headers=headers,
            files={"file": ("suspicious_commands.csv", f, "text/csv")},
            data={"log_source": "endpoint"},
        )
    assert upload_res.status_code == 201, f"Upload failed: {upload_res.text}"
    log_id = upload_res.json()["data"]["id"]
    print(f"2. Log Upload: SUCCESS (Log ID: {log_id})")

    # 3. Parse Log
    parse_res = client.post(f"/api/v1/logs/{log_id}/parse", headers=headers)
    assert parse_res.status_code == 200, f"Parse failed: {parse_res.text}"
    parsed_count = parse_res.json()["data"]["entries_created"]
    print(f"3. Log Parse: SUCCESS ({parsed_count} events parsed)")

    # 4. Sigma Detection
    detect_res = client.post(f"/api/v1/detections/run-file/{log_id}", headers=headers)
    assert detect_res.status_code == 200, f"Detection failed: {detect_res.text}"
    det_summary = detect_res.json()["data"]
    print(f"4. Sigma Detection: SUCCESS ({det_summary['detections_created']} detections created)")

    # 5. MITRE ATT&CK Matrix
    matrix_res = client.get("/api/v1/mitre/matrix", headers=headers)
    assert matrix_res.status_code == 200
    matrix = matrix_res.json()["data"]
    print(f"5. MITRE Mapping: SUCCESS ({matrix['total_tactics']} tactics, {matrix['total_detections_mapped']} detections mapped)")

    # 6. Risk Scoring
    risk_res = client.post("/api/v1/risk/assess-batch", headers=headers)
    assert risk_res.status_code == 200
    risk_data = risk_res.json()["data"]
    print(f"6. Risk Scoring: SUCCESS ({risk_data['assessed_count']} detections evaluated, avg score: {risk_data['average_score']})")

    # 7. Alert Auto-generation
    alert_gen_res = client.post("/api/v1/alerts/auto-generate", headers=headers)
    assert alert_gen_res.status_code == 200
    alert_data = alert_gen_res.json()["data"]
    print(f"7. Alert Generation: SUCCESS ({alert_data['alerts_created']} alerts created)")

    # 8. AI Threat Analysis
    det_list = client.get("/api/v1/detections", headers=headers).json()["data"]
    first_det = det_list[0]
    ai_res = client.post(f"/api/v1/ai/analyze/detection/{first_det['id']}", headers=headers)
    assert ai_res.status_code == 200
    ai_data = ai_res.json()["data"]
    print(f"8. AI Threat Analysis: SUCCESS (Provider: {ai_data['provider_used']}, Confidence: {ai_data['confidence']})")

    # 9. Automated Incident Correlation
    corr_res = client.post("/api/v1/incidents/auto-correlate", headers=headers)
    assert corr_res.status_code == 200
    corr_data = corr_res.json()["data"]
    print(f"9. Incident Correlation: SUCCESS ({corr_data['incidents_created']} incident created, {corr_data['alerts_grouped']} alerts grouped)")

    # 10. Incident Investigation Lifecycle
    inc_list = client.get("/api/v1/incidents", headers=headers).json()["data"]
    inc_id = inc_list[0]["id"]
    status_res = client.patch(f"/api/v1/incidents/{inc_id}/status", headers=headers, json={"status": "investigating"})
    assert status_res.status_code == 200
    print(f"10. Incident Lifecycle: SUCCESS (Transitioned to '{status_res.json()['data']['status']}')")

    # 11. Report Generation (PDF)
    rep_res = client.post("/api/v1/reports/generate", headers=headers, json={"report_name": "Executive-Briefing", "report_type": "pdf"})
    assert rep_res.status_code == 201
    rep_id = rep_res.json()["data"]["id"]
    print(f"11. Report Generation: SUCCESS (PDF Report ID: {rep_id})")

    # 12. Dashboard Summary
    dash_res = client.get("/api/v1/dashboard/summary", headers=headers)
    assert dash_res.status_code == 200
    dash = dash_res.json()["data"]
    print(f"12. Dashboard Summary: SUCCESS (Total Alerts: {dash['total_alerts']}, Critical: {dash['critical_alerts']}, Open Incidents: {dash['open_incidents']})")

    print("\nALL 12 END-TO-END SOC PIPELINE STAGES PASSED!")

if __name__ == "__main__":
    run_pipeline()
