"""
Comprehensive End-to-End Test Suite for Autonomous SOC Analyst Platform
Validates:
- Health & Multi-Engine Diagnostics
- Auth & RBAC
- Safe Host/IP Web Security Lab
- Telemetry Upload & Event Count Integrity
- Sigma AST Threat Detection & Forensics
- Continuous Analyst Feedback & Quality Metrics
- Deterministic Risk Scoring & Posture
- Alert Clustering & Lifecycle Transitions
- Incident Correlation & Containment
- Provenance Pipeline Trace Graph
- Global SOC Search Engine
- Immutable Security Audit Trail
"""

import sys
import time
import json
import requests

BASE_URL = "http://localhost:8000/api/v1"

def run_e2e():
    session = requests.Session()
    print("=" * 75)
    print("AUTONOMOUS SOC ANALYST — ENTERPRISE E2E PLATFORM VERIFICATION")
    print("=" * 75)

    # 1. Health Diagnostics
    print("\n[1] Checking System Health & Engine Diagnostics...")
    h_res = session.get(f"{BASE_URL}/health")
    assert h_res.status_code == 200, f"Health check failed: {h_res.text}"
    print(f"    Core API: {h_res.json().get('status', 'OK')}")

    # 2. Authenticate as Admin
    print("\n[2] Authenticating as Super Admin...")
    login_res = session.post(
        f"{BASE_URL}/auth/login",
        data={"username": "admin", "password": "Admin1234!"},
    )
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token = login_res.json().get("access_token")
    assert token, "No access token received"
    session.headers.update({"Authorization": f"Bearer {token}"})
    print("    [OK] Bearer token acquired.")

    soc_h = session.get(f"{BASE_URL}/soc-health")
    assert soc_h.status_code == 200, f"SOC Health failed: {soc_h.text}"
    sh_data = soc_h.json()
    print(f"    SOC Engine Health: {sh_data.get('overall_status')} ({sh_data.get('active_components')}/{sh_data.get('total_components')} engines)")

    # 3. Launch Safe Assessment on 127.0.0.1
    print("\n[3] Launching Authorized Safe Host Assessment (127.0.0.1)...")
    scan_res = session.post(
        f"{BASE_URL}/web-security/scans",
        json={"target_url": "http://127.0.0.1:8000", "scan_profile": "standard"}
    )
    assert scan_res.status_code == 201, f"Scan launch failed: {scan_res.text}"
    scan_data = scan_res.json()
    scan_id = scan_data.get("scan_id")
    print(f"    Scan ID: {scan_id} | Status: {scan_data.get('status')} | Target: {scan_data.get('target_host')}")
    print(f"    Posture Score: {scan_data.get('posture_score')}/100 | Findings: {scan_data.get('findings_count')}")

    # 4. Upload Telemetry Log & Verify Event Count Integrity
    print("\n[4] Uploading & Ingesting Telemetry Log File...")
    sample_csv = (
        "timestamp,source_ip,destination_ip,username,hostname,event_type,action,message\n"
        "2026-09-11T10:00:00Z,192.168.1.105,10.0.0.1,admin,workstation-01,authentication,failed,Multiple failed logon attempts\n"
        "2026-09-11T10:01:00Z,192.168.1.105,10.0.0.1,admin,workstation-01,authentication,failed,Multiple failed logon attempts\n"
        "2026-09-11T10:02:00Z,192.168.1.105,10.0.0.1,admin,workstation-01,authentication,failed,Multiple failed logon attempts\n"
        "2026-09-11T10:03:00Z,192.168.1.105,10.0.0.1,admin,workstation-01,process_creation,executed,powershell.exe -enc SQBFAFgA\n"
    ).encode("utf-8")

    files = {"file": ("auth_brute_force.csv", sample_csv, "text/csv")}
    data = {"log_source": "endpoint"}
    upload_res = session.post(f"{BASE_URL}/logs/upload", files=files, data=data)
    assert upload_res.status_code == 201, f"Log upload failed: {upload_res.text}"
    uploaded_log = upload_res.json().get("data", {})
    sec_log_id = uploaded_log.get("id")
    print(f"    Uploaded Log ID: {sec_log_id} ({uploaded_log.get('original_filename')})")

    # Parse the log
    parse_res = session.post(f"{BASE_URL}/logs/{sec_log_id}/parse")
    assert parse_res.status_code == 200, f"Parsing failed: {parse_res.text}"
    parse_summary = parse_res.json().get("data", {})
    print(f"    Parsed Entries Created: {parse_summary.get('entries_created')}")

    # Verify event_count integrity
    log_check = session.get(f"{BASE_URL}/logs/{sec_log_id}")
    assert log_check.status_code == 200, f"Fetch log failed: {log_check.text}"
    event_count = log_check.json().get("data", {}).get("event_count")
    print(f"    Verified SecurityLog.event_count: {event_count} (Must be 4)")
    assert event_count == 4, f"Expected event_count=4, got {event_count}"

    # 5. Execute Sigma Detections
    print("\n[5] Executing Sigma AST Detection Engine...")
    det_res = session.post(f"{BASE_URL}/detections/run-all")
    assert det_res.status_code == 200, f"Detection run failed: {det_res.text}"
    det_summary = det_res.json().get("data", {})
    print(f"    Detections Created: {det_summary.get('detections_created')} from {det_summary.get('events_scanned')} events")

    # Fetch list of detections
    dets_list = session.get(f"{BASE_URL}/detections", params={"limit": 5})
    assert dets_list.status_code == 200
    detections = dets_list.json().get("data", [])
    assert len(detections) > 0, "No detections returned"
    first_det = detections[0]
    first_det_id = first_det["id"]
    print(f"    Sample Detection: [{first_det['severity'].upper()}] {first_det['rule_title']} (Rule: {first_det['matched_rule']})")

    # 6. Record Analyst Verdict & Check Detection Quality
    print("\n[6] Recording Analyst Feedback & Continuous Quality Metrics...")
    fb_res = session.post(
        f"{BASE_URL}/detections/{first_det_id}/feedback",
        json={"verdict": "TRUE_POSITIVE", "note": "Verified brute force logon telemetry match."}
    )
    assert fb_res.status_code == 200, f"Feedback submission failed: {fb_res.text}"
    print("    Feedback recorded: TRUE_POSITIVE")

    qm_res = session.get(f"{BASE_URL}/detections/quality-metrics")
    assert qm_res.status_code == 200
    qm = qm_res.json().get("data", {})
    print(f"    Reviewed: {qm.get('reviewed_detections')}/{qm.get('total_detections')} | TP Rate: {qm.get('tp_rate') * 100}% | Precision: {qm.get('accuracy') * 100}%")

    # 7. Batch Risk Scoring
    print("\n[7] Assessing Deterministic Risk Scores...")
    risk_res = session.post(f"{BASE_URL}/risk/assess-batch")
    assert risk_res.status_code == 200, f"Risk assessment failed: {risk_res.text}"
    print(f"    Batch Scored: {risk_res.json().get('data', {}).get('assessed_count')} detections")

    # 8. Auto-Generate SOC Alerts
    print("\n[8] Generating SOC Alerts...")
    alert_res = session.post(f"{BASE_URL}/alerts/auto-generate")
    assert alert_res.status_code == 200, f"Alert gen failed: {alert_res.text}"
    print(f"    Alerts: {alert_res.json().get('data', {}).get('message')}")

    alerts_list = session.get(f"{BASE_URL}/alerts", params={"limit": 5})
    assert alerts_list.status_code == 200
    alerts = alerts_list.json().get("data", [])
    assert len(alerts) > 0, "No alerts available"
    first_alert = alerts[0]
    first_alert_id = first_alert["id"]
    print(f"    Sample Alert: [{first_alert['severity'].upper()}] {first_alert['title']} (Status: {first_alert['status']})")

    # Update alert status (Audited)
    patch_alt = session.patch(f"{BASE_URL}/alerts/{first_alert_id}/status", json={"status": "in_progress"})
    assert patch_alt.status_code == 200
    print("    Alert transitioned to: IN_PROGRESS")

    # 9. Auto-Correlate Incidents
    print("\n[9] Auto-Correlating Alerts into Formal Incident Dossiers...")
    inc_res = session.post(f"{BASE_URL}/incidents/auto-correlate")
    assert inc_res.status_code == 200
    print(f"    Incident Correlation: {inc_res.json().get('data', {}).get('message')}")

    inc_list = session.get(f"{BASE_URL}/incidents", params={"limit": 5})
    assert inc_list.status_code == 200
    incidents = inc_list.json().get("data", [])
    assert len(incidents) > 0, "No incidents found"
    first_inc = incidents[0]
    first_inc_id = first_inc["id"]
    print(f"    Active Incident: [{first_inc['incident_number']}] Status: {first_inc['status']}")

    # Transition incident status to INVESTIGATING (Audited)
    inc_patch = session.patch(f"{BASE_URL}/incidents/{first_inc_id}/status", json={"status": "investigating"})
    assert inc_patch.status_code == 200
    print("    Incident status transitioned to: INVESTIGATING")

    # 10. End-to-End Pipeline Provenance Trace
    print("\n[10] Testing End-to-End Pipeline Provenance Trace API...")
    trace_res = session.get(f"{BASE_URL}/pipeline/trace/incident/{first_inc_id}")
    assert trace_res.status_code == 200, f"Trace failed: {trace_res.text}"
    trace_data = trace_res.json().get("data", {})
    print(f"    Trace Stages Discovered: {trace_data.get('stages_count')}")
    for st in trace_data.get("stages", []):
        print(f"      -> [{st['stage']}] {st['name']}: {st['status']} ({st['summary']})")
    assert trace_data.get("stages_count", 0) >= 3, "Provenance chain missing expected stages"

    # Also test trace on detection
    trace_det = session.get(f"{BASE_URL}/pipeline/trace/detection/{first_det_id}")
    assert trace_det.status_code == 200
    print(f"    Trace from Detection [{first_det_id}]: {trace_det.json().get('data', {}).get('stages_count')} stages")

    # 11. Global SOC Search Engine
    print("\n[11] Testing Global SOC Intelligence Search...")
    search_queries = ["192.168", "admin", "brute", "critical", "incident"]
    for q in search_queries:
        s_res = session.get(f"{BASE_URL}/search", params={"q": q, "limit": 3})
        assert s_res.status_code == 200
        s_data = s_res.json().get("data", {})
        print(f"    Query '{q}': {s_data.get('total_matches')} matches across categories: {list(s_data.get('categories', {}).keys())}")

    # 12. Immutable Security Audit Trail Verification
    print("\n[12] Verifying Immutable Security Audit Trail...")
    audit_res = session.get(f"{BASE_URL}/audit-logs", params={"limit": 20})
    assert audit_res.status_code == 200, f"Audit query failed: {audit_res.text}"
    audit_items = audit_res.json().get("data", [])
    total_audits = audit_res.json().get("total", 0)
    print(f"    Total Audit Records in Database: {total_audits}")
    recorded_actions = {a["action"] for a in audit_items}
    print(f"    Recorded Operations in Log: {sorted(list(recorded_actions))}")

    expected_actions = {"USER_LOGIN", "LOG_UPLOAD", "DETECTION_FEEDBACK", "ALERT_STATUS_UPDATE", "INCIDENT_STATUS_UPDATE", "SECURITY_SCAN_RUN"}
    missing = expected_actions - recorded_actions
    assert not missing, f"Missing expected audit actions: {missing}"
    print("    [OK] ALL required operational actions were persisted in the audit trail!")

    print("\n" + "=" * 75)
    print("SUCCESS: 100% OF ADVANCED SOC PIPELINE TESTS PASSED VERIFICATION!")
    print("=" * 75)

if __name__ == "__main__":
    run_e2e()
