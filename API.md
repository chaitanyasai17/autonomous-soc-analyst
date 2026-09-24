# Autonomous SOC Analyst (ASOC) — REST API Documentation

Base URL: `http://localhost:8000/api/v1`
Interactive Swagger Documentation: `http://localhost:8000/docs`
ReDoc Specification: `http://localhost:8000/redoc`

---

## 1. Authentication & Users (`/auth`, `/users`)

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/auth/register` | Register a new analyst or viewer account | No |
| `POST` | `/auth/login` | OAuth2 password form login; returns JWT access/refresh token | No |
| `POST` | `/auth/refresh` | Exchange refresh token for new access token | No |
| `POST` | `/auth/logout` | Revoke session and invalidate tokens | Yes (Bearer) |
| `GET` | `/auth/me` | Fetch authenticated user profile & permissions | Yes (Bearer) |
| `POST` | `/auth/change-password` | Rotate analyst account password | Yes (Bearer) |
| `GET` | `/users` | List and search user accounts (Admin only) | Yes (Admin) |

---

## 2. Health & Telemetry (`/health`, `/dashboard`)

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/health` | Root liveness probe (service status, version) | No |
| `GET` | `/api/v1/health` | Versioned health status probe | No |
| `GET` | `/dashboard/summary` | Aggregate metrics (alerts, incidents, risk, MITRE hits) | Yes (Bearer) |

---

## 3. Log Ingestion & Parsing (`/logs`, `/parsed-logs`)

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/logs/upload` | Upload CSV, JSON, Syslog, TXT security logs (multipart) | Yes (Bearer) |
| `GET` | `/logs` | List, search, filter, and paginate uploaded files | Yes (Bearer) |
| `GET` | `/logs/{id}` | Retrieve specific uploaded log file metadata | Yes (Bearer) |
| `GET` | `/logs/{id}/download` | Authenticated raw log file download | Yes (Bearer) |
| `POST` | `/logs/{id}/parse` | Parse raw log into normalized `ParsedLog` events | Yes (Bearer) |
| `POST` | `/logs/{id}/reparse` | Force re-parsing of an uploaded log | Yes (Bearer) |
| `GET` | `/logs/statistics` | Upload volume, file types, and parser metrics | Yes (Bearer) |
| `GET` | `/parsed-logs` | Filter normalized events across timestamp, IPs, users | Yes (Bearer) |

---

## 4. Sigma Detections (`/sigma-rules`, `/detections`)

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/sigma-rules` | List all compiled YAML Sigma rules | Yes (Bearer) |
| `GET` | `/sigma-rules/{id}` | Get AST definition, conditions, and metadata | Yes (Bearer) |
| `POST` | `/detections/run-all` | Execute all enabled Sigma rules on visible parsed logs | Yes (Bearer) |
| `POST` | `/detections/run/{parsed_log_id}` | Execute rules against a single parsed event | Yes (Bearer) |
| `GET` | `/detections` | List, search, and filter triggered security detections | Yes (Bearer) |
| `GET` | `/detections/{id}` | Get detection details and matched payload fields | Yes (Bearer) |
| `GET` | `/detections/{id}/mitre` | Get mapped MITRE ATT&CK tactics & techniques | Yes (Bearer) |

---

## 5. MITRE ATT&CK Framework (`/mitre`)

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/mitre/tactics` | List all 14 Enterprise Tactics (`TA0001`–`TA0043`) | Yes (Bearer) |
| `GET` | `/mitre/matrix` | Full Enterprise matrix with active detection counts | Yes (Bearer) |
| `GET` | `/mitre/techniques` | Search, filter, and list techniques | Yes (Bearer) |
| `GET` | `/mitre/techniques/{id}` | Get technique details and external reference links | Yes (Bearer) |
| `GET` | `/mitre/search?q={query}` | Search techniques by keyword or ID | Yes (Bearer) |
| `POST` | `/mitre/seed` | Seed/re-synchronize ATT&CK catalog | Yes (Bearer) |

---

## 6. AI Threat Analysis & Risk Engine (`/ai`, `/risk`)

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/ai/status` | Current AI provider status (Ollama / OpenAI / Heuristic) | Yes (Bearer) |
| `POST` | `/ai/analyze/detection/{id}` | Generate attack narrative, false positive check, IOCs | Yes (Bearer) |
| `POST` | `/risk/assess/{detection_id}` | Calculate deterministic 0–100 risk score and breakdown | Yes (Bearer) |
| `POST` | `/risk/assess-batch` | Batch calculate risk scores for unassessed detections | Yes (Bearer) |
| `GET` | `/risk/statistics` | Risk score distribution and level counters | Yes (Bearer) |

---

## 7. Alerts & Incidents (`/alerts`, `/incidents`)

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/alerts` | List, filter, sort alerts by severity, status, date | Yes (Bearer) |
| `POST` | `/alerts/auto-generate` | Generate alerts for unalerted risk assessments | Yes (Bearer) |
| `PATCH` | `/alerts/{id}/status` | Transition alert status (`open`, `in_progress`, `resolved`) | Yes (Bearer) |
| `GET` | `/incidents` | List investigation cases (`INC-YYYY-XXXX`) | Yes (Bearer) |
| `POST` | `/incidents/auto-correlate` | Cluster orphaned alerts into correlated incident cases | Yes (Bearer) |
| `GET` | `/incidents/{id}` | Full investigation dossier with correlated alerts | Yes (Bearer) |
| `PATCH` | `/incidents/{id}/status` | Transition lifecycle (`investigating`, `contained`, `resolved`) | Yes (Bearer) |

---

## 8. Reports & Notifications (`/reports`, `/notifications`)

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/reports/generate` | Compile executive ReportLab PDF or CSV telemetry | Yes (Bearer) |
| `GET` | `/reports` | List generated compliance & audit reports | Yes (Bearer) |
| `GET` | `/reports/{id}/download` | Download compiled report artifact | Yes (Bearer) |
| `GET` | `/notifications` | List user notification activity feed | Yes (Bearer) |
| `GET` | `/notifications/unread-count`| Get current unread notification badge counter | Yes (Bearer) |
| `PATCH` | `/notifications/{id}/read` | Mark individual notification as read | Yes (Bearer) |
| `POST` | `/notifications/read-all` | Mark all notifications as read | Yes (Bearer) |
