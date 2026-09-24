# AI-Powered Autonomous SOC Analyst (ASOC)

An enterprise-grade, AI-assisted Security Operations Center (SOC) platform for intelligent threat detection and incident response.

> **Status:** 🛡️ **COMPLETE & PRODUCTION READY** (Parts 1–17 Fully Implemented & Verified).

---

## 🌟 Overview & Key Capabilities

The **Autonomous SOC Analyst (ASOC)** platform provides automated, end-to-end security operations:

- 🔐 **Zero-Trust Identity & RBAC:** JWT rotation, password hashing, and granular role enforcement (`super_admin`, `admin`, `soc_manager`, `analyst`, `viewer`).
- 📁 **Multi-Format Log Ingestion & Parsing:** Upload CSV, JSON, Syslog (RFC 3164/5424), and unstructured text logs with automatic field normalization.
- ⚡ **Sigma Rule Detection Engine:** High-performance AST evaluation of Sigma rules with regex, wildcard, and condition logic.
- 🎯 **MITRE ATT&CK Matrix Navigator:** Interactive visualization of all 14 enterprise tactics and mapped detection telemetry.
- 🤖 **AI Threat Hunter Copilot:** Automated attack narrative synthesis, false-positive triage, IOC extraction, and remediation playbooks (supports Ollama, OpenAI, and resilient offline Heuristic fallback).
- 📊 **Deterministic Risk Scoring Engine:** Transparent 0–100 composite scoring combining rule severity, confidence, MITRE weights, and asset context.
- 🚨 **Case & Incident Management:** Collision-free `INC-YYYY-XXXX` case generation, auto-correlation of unlinked alerts, and SOC lifecycle state machine (`OPEN` → `INVESTIGATING` → `CONTAINED` → `RESOLVED` → `CLOSED`).
- 📈 **Enterprise Dark SOC Frontend:** Responsive React 18 dashboard, interactive visualizers, live investigation workbench, and quick action bars.
- 📄 **Executive Reports & Audits:** Printable PDF briefs (ReportLab) and CSV telemetry exports.
- 🔔 **In-App Notification Center:** Real-time priority alert notifications with unread counts and batch actions.

---

## 🚀 Live Localhost URLs

When running locally:
- **Frontend Web UI:** [http://localhost:5173](http://localhost:5173)
- **FastAPI Backend Server:** [http://localhost:8000](http://localhost:8000)
- **Root Health Endpoint:** [http://localhost:8000/health](http://localhost:8000/health)
- **Swagger Interactive API Documentation:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc API Documentation:** [http://localhost:8000/redoc](http://localhost:8000/redoc)

## Authentication

Authentication is required to access the SOC platform.
Administrator credentials are configured through environment variables
or the application's secure initialization process.

Never commit production credentials, passwords, API keys, JWT secrets,
or database credentials to the repository.

### Local Administrator Configuration

For local development, copy `.env.example` to `.env` and specify your credentials:

```env
ADMIN_USERNAME=admin
ADMIN_PASSWORD=<SET_LOCALLY>
ADMIN_ROLE=super_admin
```

When the backend initializes, the administrator account is provisioned with the password securely hashed via bcrypt.

---

## 🛠️ Quick Start Guide

### 1. Running Locally (Zero-Dependency SQLite Mode)

#### Start Backend:
```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

#### Start Frontend:
```bash
cd frontend
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

### 2. Running with Docker Compose (Production Multi-Container)

```bash
docker-compose up --build -d
```
Services spun up:
- `asoc_postgres`: PostgreSQL 16
- `asoc_backend`: FastAPI Backend on port 8000
- `asoc_frontend`: React + Vite SPA
- `asoc_nginx`: Reverse Proxy on port 80

---

## 🧪 Automated Testing

Run the comprehensive 22-test automated test suite:
```bash
cd backend
python -m unittest discover -s tests -p "test_*.py"
```

To run the end-to-end 12-stage SOC pipeline verification test:
```bash
cd backend
python test_pipeline.py
```

---

## 📂 Project Architecture

```
autonomous-soc-analyst/
├── backend/                  # FastAPI Application (Clean Architecture)
│   ├── app/
│   │   ├── ai/              # Multi-provider AI Threat Hunter (Ollama, OpenAI, Heuristic)
│   │   ├── api/v1/          # 72+ REST API endpoints & route controllers
│   │   ├── database/        # SQLAlchemy 2.0 ORM & SQLite/PostgreSQL compatibility
│   │   ├── detection/       # Real-time event detection pipelines
│   │   ├── mitre/           # MITRE ATT&CK Enterprise Matrix & dataset
│   │   ├── models/          # ORM database models
│   │   ├── repositories/    # Clean architecture repository pattern
│   │   ├── risk/            # Deterministic 0-100 composite risk scoring engine
│   │   ├── schemas/         # Pydantic v2 schemas & request/response validation
│   │   ├── services/        # Business logic services
│   │   └── sigma/           # Sigma rule AST parser & evaluation engine
│   ├── migrations/          # Alembic database migrations
│   ├── storage/             # File storage (logs, reports, rules)
│   └── tests/               # Unit & integration test suites
├── frontend/                 # React 18 + Vite + TypeScript Application
│   ├── src/
│   │   ├── components/      # Common UI components (DataTable, Modal, Badge, StatCard)
│   │   ├── contexts/        # Auth and notification contexts
│   │   ├── layouts/         # SOC dark dashboard layout with sidebar & navbar
│   │   ├── pages/           # 14 complete SOC analyst operational pages
│   │   ├── services/        # Axios API clients & interceptors
│   │   └── types/           # Complete TypeScript domain definitions
├── docker/                   # Multi-stage production container definitions
│   ├── backend/             # Python 3.11 builder & hardened runtime Dockerfile
│   ├── frontend/            # Node build to Nginx Alpine Dockerfile
│   └── nginx/               # Production reverse proxy configuration
├── docker-compose.yml        # Full-stack container orchestration
├── examples/sample-logs/     # Realistic security logs for ingestion testing
└── PROJECT_STATUS.md         # Comprehensive verification report
```
