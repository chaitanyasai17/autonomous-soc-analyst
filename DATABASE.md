# Autonomous SOC Analyst (ASOC) — Database & Data Model Specification

## 1. ORM & Engine Architecture

The platform uses **SQLAlchemy 2.0** with dual-engine compatibility:
* **Production**: PostgreSQL 16+ (with native `JSONB`, `UUID`, and foreign key constraints).
* **Local Development & Testing**: SQLite (using transparent compatibility hooks for JSON and UUID).

```text
Database URL Format:
postgresql://asoc_user:asoc_password@localhost:5432/asoc_db
sqlite:///./asoc.db
```

---

## 2. Core Entities & Relationships

```mermaid
erDiagram
    USERS ||--o{ SECURITY_LOGS : "uploads"
    USERS ||--o{ ALERTS : "assigned_to"
    USERS ||--o{ INCIDENTS : "owns"
    USERS ||--o{ NOTIFICATIONS : "receives"
    SECURITY_LOGS ||--o{ PARSED_LOGS : "normalizes"
    PARSED_LOGS ||--o{ SIGMA_DETECTIONS : "triggers"
    SIGMA_DETECTIONS ||--o{ RISK_ASSESSMENTS : "evaluated_by"
    RISK_ASSESSMENTS ||--o{ ALERTS : "promoted_to"
    INCIDENTS ||--o{ ALERTS : "correlates"
    SIGMA_DETECTIONS }o--o{ MITRE_TECHNIQUES : "maps"
```

### Table Definitions:

1. **`users`**:
   * `id` (UUID, Primary Key)
   * `username` (VARCHAR, Unique Index)
   * `email` (VARCHAR, Unique Index)
   * `password_hash` (VARCHAR, Bcrypt / Argon2)
   * `role` (ENUM: `super_admin`, `admin`, `soc_manager`, `analyst`, `viewer`)
   * `is_active` (BOOLEAN)
   * `created_at`, `updated_at`, `deleted_at` (TIMESTAMPTZ)

2. **`security_logs`**:
   * `id` (UUID, PK), `filename`, `file_path`, `file_size`, `log_source`, `processing_status`, `uploaded_by_id`.

3. **`parsed_logs`**:
   * `id` (UUID, PK), `security_log_id`, `timestamp`, `source_ip`, `destination_ip`, `username`, `event_type`, `severity`, `raw_data` (JSONB).

4. **`sigma_detections`**:
   * `id` (UUID, PK), `parsed_log_id`, `matched_rule`, `rule_title`, `severity`, `confidence`, `matched_fields` (JSONB).

5. **`mitre_techniques`**:
   * `id` (UUID, PK), `technique_id` (`T1059`), `technique_name`, `tactic` (`execution`), `description`, `reference_url`.

6. **`risk_assessments`**:
   * `id` (UUID, PK), `detection_id`, `risk_score` (FLOAT 0–100), `risk_level` (ENUM), `contributing_factors` (JSONB).

7. **`alerts`**:
   * `id` (UUID, PK), `risk_assessment_id`, `incident_id`, `title`, `severity`, `status` (ENUM), `assigned_to_id`.

8. **`incidents`**:
   * `id` (UUID, PK), `incident_number` (`INC-YYYY-XXXX`), `title`, `priority`, `status` (`OPEN`, `INVESTIGATING`, `CONTAINED`, `RESOLVED`, `CLOSED`), `owner_id`.

---

## 3. Alembic Migrations

All schema changes are tracked via linear Alembic migrations in `backend/migrations/versions/`.

```bash
# Apply pending migrations
alembic upgrade head

# Check current revision status
alembic current
```
Current Head Revision: `36887004e260`
