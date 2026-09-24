"""create initial tables

Revision ID: 926b474f0a22
Revises:
Create Date: 2026-07-16 04:18:00

This migration was authored by hand to exactly mirror what
`alembic revision --autogenerate` would produce against the ORM models in
app/models/ as of Part 3 — Database Foundation. It was not executed against
a live database (per Part 3 instructions); run it manually per
backend/migrations/README.md once a real PostgreSQL instance is available.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "926b474f0a22"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# --- Native PostgreSQL enum type definitions (created once, reused) ---
# create_type=False is required here: without it, SQLAlchemy also emits an
# automatic CREATE TYPE as part of create_table()'s DDL for any column using
# one of these types, colliding with the explicit .create() calls in
# upgrade() below (DuplicateObject error). Explicit create()/drop() calls
# remain the single source of truth for these types' lifecycle.
user_role_enum = postgresql.ENUM(
    "admin", "soc_manager", "analyst", "viewer", name="user_role", create_type=False
)
risk_level_enum = postgresql.ENUM(
    "low", "medium", "high", "critical", name="risk_level", create_type=False
)
log_source_enum = postgresql.ENUM(
    "firewall",
    "ids_ips",
    "endpoint",
    "server",
    "application",
    "cloud",
    "network_device",
    "other",
    name="log_source",
    create_type=False,
)
processing_status_enum = postgresql.ENUM(
    "pending", "processing", "completed", "failed", name="processing_status", create_type=False
)
alert_status_enum = postgresql.ENUM(
    "open",
    "in_progress",
    "resolved",
    "closed",
    "false_positive",
    name="alert_status",
    create_type=False,
)
incident_status_enum = postgresql.ENUM(
    "open",
    "investigating",
    "contained",
    "resolved",
    "closed",
    name="incident_status",
    create_type=False,
)
notification_type_enum = postgresql.ENUM(
    "alert_created",
    "incident_assigned",
    "risk_escalation",
    "report_ready",
    "system",
    name="notification_type",
    create_type=False,
)
report_type_enum = postgresql.ENUM("pdf", "csv", name="report_type", create_type=False)


def upgrade() -> None:
    bind = op.get_bind()

    # --- Create native enum types first ---
    user_role_enum.create(bind, checkfirst=True)
    risk_level_enum.create(bind, checkfirst=True)
    log_source_enum.create(bind, checkfirst=True)
    processing_status_enum.create(bind, checkfirst=True)
    alert_status_enum.create(bind, checkfirst=True)
    incident_status_enum.create(bind, checkfirst=True)
    notification_type_enum.create(bind, checkfirst=True)
    report_type_enum.create(bind, checkfirst=True)

    # --- users ---
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("username", sa.String(50), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("first_name", sa.String(100), nullable=False),
        sa.Column("last_name", sa.String(100), nullable=False),
        sa.Column("role", user_role_enum, nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
    )
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    # --- security_logs ---
    op.create_table(
        "security_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("filename", sa.String(255), nullable=False),
        sa.Column("original_filename", sa.String(255), nullable=False),
        sa.Column("log_source", log_source_enum, nullable=False),
        sa.Column("file_type", sa.String(20), nullable=False),
        sa.Column("uploaded_by_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("upload_time", sa.DateTime(timezone=True), nullable=False),
        sa.Column("processing_status", processing_status_enum, nullable=False),
        sa.ForeignKeyConstraint(["uploaded_by_id"], ["users.id"], ondelete="RESTRICT"),
    )
    op.create_index("ix_security_logs_processing_status", "security_logs", ["processing_status"])
    op.create_index("ix_security_logs_upload_time", "security_logs", ["upload_time"])

    # --- parsed_logs ---
    op.create_table(
        "parsed_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("security_log_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.Column("source_ip", sa.String(45), nullable=True),
        sa.Column("destination_ip", sa.String(45), nullable=True),
        sa.Column("hostname", sa.String(255), nullable=True),
        sa.Column("username", sa.String(100), nullable=True),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("severity", risk_level_enum, nullable=False),
        sa.Column("raw_log", sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(["security_log_id"], ["security_logs.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_parsed_logs_timestamp", "parsed_logs", ["timestamp"])
    op.create_index("ix_parsed_logs_source_ip", "parsed_logs", ["source_ip"])
    op.create_index("ix_parsed_logs_destination_ip", "parsed_logs", ["destination_ip"])
    op.create_index("ix_parsed_logs_hostname", "parsed_logs", ["hostname"])
    op.create_index("ix_parsed_logs_severity", "parsed_logs", ["severity"])

    # --- mitre_techniques ---
    op.create_table(
        "mitre_techniques",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("technique_id", sa.String(20), nullable=False),
        sa.Column("technique_name", sa.String(255), nullable=False),
        sa.Column("tactic", sa.String(100), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("reference_url", sa.String(500), nullable=True),
    )
    op.create_index("ix_mitre_techniques_technique_id", "mitre_techniques", ["technique_id"], unique=True)
    op.create_index("ix_mitre_techniques_tactic", "mitre_techniques", ["tactic"])

    # --- sigma_detections ---
    op.create_table(
        "sigma_detections",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("parsed_log_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("matched_rule", sa.String(255), nullable=False),
        sa.Column("rule_title", sa.String(255), nullable=False),
        sa.Column("severity", risk_level_enum, nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("detection_timestamp", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["parsed_log_id"], ["parsed_logs.id"], ondelete="CASCADE"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_sigma_detections_confidence_range"),
    )
    op.create_index("ix_sigma_detections_severity", "sigma_detections", ["severity"])
    op.create_index("ix_sigma_detections_detection_timestamp", "sigma_detections", ["detection_timestamp"])

    # --- sigma_detection_mitre_technique (association table) ---
    op.create_table(
        "sigma_detection_mitre_technique",
        sa.Column("sigma_detection_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("mitre_technique_id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.ForeignKeyConstraint(["sigma_detection_id"], ["sigma_detections.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["mitre_technique_id"], ["mitre_techniques.id"], ondelete="CASCADE"),
    )

    # --- risk_assessments ---
    op.create_table(
        "risk_assessments",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("sigma_detection_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False),
        sa.Column("risk_level", risk_level_enum, nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("calculated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["sigma_detection_id"], ["sigma_detections.id"], ondelete="CASCADE"),
        sa.CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_risk_assessments_score_range"),
        sa.CheckConstraint("confidence >= 0 AND confidence <= 1", name="ck_risk_assessments_confidence_range"),
    )
    op.create_index("ix_risk_assessments_risk_level", "risk_assessments", ["risk_level"])
    op.create_index("ix_risk_assessments_calculated_at", "risk_assessments", ["calculated_at"])

    # --- incidents ---
    op.create_table(
        "incidents",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("incident_number", sa.String(50), nullable=False),
        sa.Column("priority", risk_level_enum, nullable=False),
        sa.Column("status", incident_status_enum, nullable=False),
        sa.Column("opened_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("closed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["owner_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_incidents_incident_number", "incidents", ["incident_number"], unique=True)
    op.create_index("ix_incidents_status", "incidents", ["status"])
    op.create_index("ix_incidents_priority", "incidents", ["priority"])
    op.create_index("ix_incidents_opened_at", "incidents", ["opened_at"])

    # --- alerts ---
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("severity", risk_level_enum, nullable=False),
        sa.Column("status", alert_status_enum, nullable=False),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("risk_assessment_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("incident_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("assigned_to_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["risk_assessment_id"], ["risk_assessments.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["incident_id"], ["incidents.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["assigned_to_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_alerts_severity", "alerts", ["severity"])
    op.create_index("ix_alerts_status", "alerts", ["status"])
    op.create_index("ix_alerts_created_at", "alerts", ["created_at"])

    # --- notifications ---
    op.create_table(
        "notifications",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("recipient_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("notification_type", notification_type_enum, nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("message", sa.Text(), nullable=False),
        sa.Column("is_read", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("sent_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["recipient_id"], ["users.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_notifications_is_read", "notifications", ["is_read"])
    op.create_index("ix_notifications_sent_at", "notifications", ["sent_at"])

    # --- reports ---
    op.create_table(
        "reports",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("report_name", sa.String(255), nullable=False),
        sa.Column("report_type", report_type_enum, nullable=False),
        sa.Column("generated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("file_path", sa.String(500), nullable=False),
        sa.Column("generated_by_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.ForeignKeyConstraint(["generated_by_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_reports_report_type", "reports", ["report_type"])
    op.create_index("ix_reports_generated_at", "reports", ["generated_at"])


def downgrade() -> None:
    bind = op.get_bind()

    # Drop tables in reverse dependency order.
    op.drop_table("reports")
    op.drop_table("notifications")
    op.drop_table("alerts")
    op.drop_table("incidents")
    op.drop_table("risk_assessments")
    op.drop_table("sigma_detection_mitre_technique")
    op.drop_table("sigma_detections")
    op.drop_table("mitre_techniques")
    op.drop_table("parsed_logs")
    op.drop_table("security_logs")
    op.drop_table("users")

    # Drop enum types last (nothing references them once tables are gone).
    report_type_enum.drop(bind, checkfirst=True)
    notification_type_enum.drop(bind, checkfirst=True)
    incident_status_enum.drop(bind, checkfirst=True)
    alert_status_enum.drop(bind, checkfirst=True)
    processing_status_enum.drop(bind, checkfirst=True)
    log_source_enum.drop(bind, checkfirst=True)
    risk_level_enum.drop(bind, checkfirst=True)
    user_role_enum.drop(bind, checkfirst=True)
