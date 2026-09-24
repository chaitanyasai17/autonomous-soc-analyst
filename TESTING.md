# Autonomous SOC Analyst (ASOC) — Testing & QA Guide

## 1. Automated Test Suite Execution

The backend contains 23 automated unit, integration, and end-to-end tests:

```bash
cd backend

# Execute all tests
python -m unittest discover -s tests -p "test_*.py"
```

### Test Suite Structure:
```text
backend/tests/
├── unit/
│   ├── test_sigma_compiler.py    # Validates YAML AST compiler, conditions, and modifiers
│   ├── test_risk_engine.py       # Validates 0–100 deterministic risk formula and bounds
│   └── test_ai_fallback.py       # Validates heuristic resilience and zero-downtime fallback
├── integration/
│   ├── test_api_endpoints.py     # Validates REST API responses with TestClient
│   ├── test_incident_lifecycle.py# Validates OPEN -> INVESTIGATING -> RESOLVED state machine
│   └── test_mitre_mapping.py     # Validates MITRE technique tags & detection linkage
└── e2e/
    └── test_complete_workflow.py # Full 14-stage lifecycle pipeline test
```

---

## 2. End-to-End Pipeline Verification

The test `test_complete_soc_e2e_pipeline` in `tests/e2e/test_complete_workflow.py` executes and asserts the complete autonomous chain:

```text
1. Register & Login (analyst account created, JWT token returned)
2. Upload Security Log (CSV/JSON telemetry staged safely)
3. Parse Log (Normalized into ParsedLog records)
4. Sigma Detection (AST engine matches living-off-the-land pattern)
5. MITRE Mapping (Associated with TA0002 Execution & T1059)
6. Risk Score (Deterministic formula evaluates score ~81.5/100)
7. Alert Generation (Promoted to high-priority triage queue)
8. AI Threat Analysis (Attack narrative & IOCs synthesized)
9. Incident Correlation (Grouped into case INC-YYYY-XXXX)
10. Investigation (Analyst transitions case to INVESTIGATING)
11. Containment (Host endpoint quarantined via active response)
12. Resolution (Incident marked as RESOLVED)
13. Report Generation (Executive PDF briefing & CSV export compiled)
14. Notification (Real-time in-app alerts dispatched and verified)
```

---

## 3. Frontend Production Build Verification

Verify that the React frontend builds without TypeScript compilation warnings or bundling errors:

```bash
cd frontend
npm run build
```

Expected result:
```text
✓ 1650 modules transformed.
dist/index.html                   0.92 kB │ gzip:   0.53 kB
dist/assets/index-BvCrX8pn.css   43.97 kB │ gzip:   7.86 kB
dist/assets/index-DHTahJws.js   440.29 kB │ gzip: 118.49 kB
✓ built in ~7s
```
