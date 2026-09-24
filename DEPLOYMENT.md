# Autonomous SOC Analyst (ASOC) — Deployment Guide

## 1. Local Development Execution

### Prerequisites
* Python 3.10+ (tested on Python 3.11/3.14)
* Node.js 18+ & npm 9+
* Git

### Backend Setup:
```bash
cd backend

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # Or `.\venv\Scripts\Activate.ps1` on Windows

# Install dependencies
pip install -r requirements.txt

# Run migrations
alembic upgrade head

# Start FastAPI server
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```
Server runs on: `http://localhost:8000` (API: `http://localhost:8000/docs`)

### Frontend Setup:
```bash
cd frontend

# Install dependencies
npm install

# Start Vite dev server
npm run dev -- --host 0.0.0.0 --port 5173
```
Frontend runs on: `http://localhost:5173`

---

## 2. Production Docker Compose Deployment

The full stack can be built and started with a single command:

```bash
docker compose up --build -d
```

### Container Topology:
1. **`asoc_postgres`**: PostgreSQL 16 Alpine on port `5432` with persistent storage volume `postgres_data`.
2. **`asoc_backend`**: FastAPI Python 3.11 on port `8000` running under unprivileged user `asocuser`.
3. **`asoc_frontend`**: React 18 production bundle compiled into Nginx Alpine on port `80`.
4. **`asoc_nginx`**: Edge reverse proxy on port `80`/`443` handling SSL termination and routing.

---

## 3. Environment Variables Reference

Copy `.env.example` to `.env`:

| Variable | Default Value | Purpose |
|---|---|---|
| `APP_NAME` | `ASOC — Autonomous SOC Analyst` | Service branding |
| `APP_ENV` | `development` / `production` | Runtime mode |
| `DATABASE_URL` | `postgresql://asoc_user:...@localhost:5432/asoc_db` | Database connection string |
| `JWT_SECRET_KEY` | *(cryptographic string)* | HMAC-SHA256 signature key |
| `JWT_ACCESS_TOKEN_EXPIRE_MINUTES` | `60` | Access token lifespan |
| `AI_PROVIDER` | `heuristic` (or `ollama`, `openai`)| Threat hunter backend |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Local LLM daemon address |
| `UPLOAD_DIRECTORY` | `uploads/security_logs` | Staged log storage |
| `MAX_UPLOAD_SIZE_MB` | `50` | Maximum file ceiling |
