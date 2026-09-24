"""add web security testing and advanced soc capabilities

Revision ID: a1b2c3d4e5f6
Revises: 36887004e260
Create Date: 2026-09-09 22:30:00

Additive migration:
- Adds web_security_allowlist table
- Adds web_security_scans table
- Adds web_security_findings table
- Adds ioc_records table
- Adds web_finding_id column to alerts
- Adds analyst_verdict and analyst_note columns to sigma_detections
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from app.models.sa_types import risk_level_enum

# revision identifiers, used by Alembic.
revision: str = "a1b2c3d4e5f6"
down_revision: Union[str, None] = "36887004e260"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. web_security_allowlist
    op.create_table(
        "web_security_allowlist",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("pattern", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.true()),
        sa.Column("created_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("created_by_username", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    op.create_index("ix_web_security_allowlist_pattern", "web_security_allowlist", ["pattern"], unique=True)
    op.create_index("ix_web_security_allowlist_is_active", "web_security_allowlist", ["is_active"])

    # 2. web_security_scans
    op.create_table(
        "web_security_scans",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", sa.String(50), nullable=False),
        sa.Column("target_url", sa.String(1024), nullable=False),
        sa.Column("target_host", sa.String(255), nullable=False),
        sa.Column("scan_profile", sa.String(50), nullable=False, server_default="standard"),
        sa.Column("status", sa.String(50), nullable=False, server_default="queued"),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("pages_checked", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("endpoints_checked", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("critical_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("high_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("medium_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("low_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("posture_score", sa.Float(), nullable=False, server_default="100.0"),
        sa.Column("posture_breakdown", postgresql.JSONB(), nullable=True),
        sa.Column("initiated_by_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL"), nullable=True),
        sa.Column("initiated_by_username", sa.String(100), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    op.create_index("ix_web_security_scans_scan_id", "web_security_scans", ["scan_id"], unique=True)
    op.create_index("ix_web_security_scans_status", "web_security_scans", ["status"])
    op.create_index("ix_web_security_scans_started_at", "web_security_scans", ["started_at"])
    op.create_index("ix_web_security_scans_target_host", "web_security_scans", ["target_host"])

    # 3. web_security_findings
    op.create_table(
        "web_security_findings",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("scan_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("web_security_scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("finding_id", sa.String(50), nullable=False),
        sa.Column("title", sa.String(255), nullable=False),
        sa.Column("category", sa.String(100), nullable=False),
        sa.Column("severity", risk_level_enum, nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("status", sa.String(50), nullable=False, server_default="CONFIRMED"),
        sa.Column("endpoint", sa.String(1024), nullable=False),
        sa.Column("http_method", sa.String(10), nullable=False, server_default="GET"),
        sa.Column("parameter", sa.String(255), nullable=True),
        sa.Column("evidence", sa.Text(), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("remediation", sa.Text(), nullable=False),
        sa.Column("cwe_id", sa.String(50), nullable=True),
        sa.Column("owasp_category", sa.String(100), nullable=True),
        sa.Column("mitre_technique_id", sa.String(50), nullable=True),
        sa.Column("affected_component", sa.String(255), nullable=True),
        sa.Column("discovered_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("risk_score", sa.Float(), nullable=False, server_default="0.0"),
        sa.Column("related_alert_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("related_incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("analyst_notes", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    op.create_index("ix_web_security_findings_scan_id", "web_security_findings", ["scan_id"])
    op.create_index("ix_web_security_findings_finding_id", "web_security_findings", ["finding_id"], unique=True)
    op.create_index("ix_web_security_findings_severity", "web_security_findings", ["severity"])
    op.create_index("ix_web_security_findings_category", "web_security_findings", ["category"])
    op.create_index("ix_web_security_findings_status", "web_security_findings", ["status"])
    op.create_index("ix_web_security_findings_endpoint", "web_security_findings", ["endpoint"])

    # 4. ioc_records
    op.create_table(
        "ioc_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("ioc_type", sa.String(50), nullable=False),
        sa.Column("value", sa.String(1024), nullable=False),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False, server_default="1.0"),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("related_alert_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True),
        sa.Column("related_incident_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("tags", postgresql.JSONB(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    op.create_index("ix_ioc_records_type_value", "ioc_records", ["ioc_type", "value"], unique=True)
    op.create_index("ix_ioc_records_type", "ioc_records", ["ioc_type"])
    op.create_index("ix_ioc_records_last_seen", "ioc_records", ["last_seen"])

    # 5. Alert additions
    op.add_column("alerts", sa.Column("web_finding_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("web_security_findings.id", ondelete="SET NULL"), nullable=True))

    # 6. SigmaDetection additions
    op.add_column("sigma_detections", sa.Column("analyst_verdict", sa.String(50), nullable=True))
    op.add_column("sigma_detections", sa.Column("analyst_note", sa.Text(), nullable=True))


def downgrade() -> None:
    op.drop_column("sigma_detections", "analyst_note")
    op.drop_column("sigma_detections", "analyst_verdict")
    op.drop_column("alerts", "web_finding_id")
    op.drop_table("ioc_records")
    op.drop_table("web_security_findings")
    op.drop_table("web_security_scans")
    op.drop_table("web_security_allowlist")
