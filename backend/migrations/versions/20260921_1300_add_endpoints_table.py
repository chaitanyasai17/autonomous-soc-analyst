"""add endpoints table for authorized host management

Revision ID: d4e5f6a7b8c9
Revises: c3d4e5f6a7b8
Create Date: 2026-09-21 13:00:00

Additive migration:
- Adds endpoints table to manage, monitor, and isolate enrolled SOC endpoints
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from app.models.sa_types import risk_level_enum

# revision identifiers, used by Alembic.
revision: str = "d4e5f6a7b8c9"
down_revision: Union[str, None] = "c3d4e5f6a7b8"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "endpoints",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("hostname", sa.String(255), nullable=False),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("mac_address", sa.String(50), nullable=True),
        sa.Column("operating_system", sa.String(100), nullable=False, server_default="Windows 11 Enterprise"),
        sa.Column("os_version", sa.String(50), nullable=True, server_default="23H2"),
        sa.Column("agent_version", sa.String(50), nullable=False, server_default="1.4.2-asoc"),
        sa.Column("status", sa.String(20), nullable=False, server_default="online"),
        sa.Column("risk_level", risk_level_enum, nullable=False, server_default="low"),
        sa.Column("owner_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("is_isolated", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("isolation_reason", sa.String(255), nullable=True),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("tags", postgresql.JSONB(), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), onupdate=sa.func.now(), nullable=False),
    )
    op.create_index("ix_endpoints_hostname", "endpoints", ["hostname"], unique=True)
    op.create_index("ix_endpoints_ip_address", "endpoints", ["ip_address"])
    op.create_index("ix_endpoints_status", "endpoints", ["status"])
    op.create_index("ix_endpoints_risk_level", "endpoints", ["risk_level"])
    op.create_index("ix_endpoints_owner_id", "endpoints", ["owner_id"])
    op.create_index("ix_endpoints_last_seen", "endpoints", ["last_seen"])


def downgrade() -> None:
    op.drop_index("ix_endpoints_last_seen", table_name="endpoints")
    op.drop_index("ix_endpoints_owner_id", table_name="endpoints")
    op.drop_index("ix_endpoints_risk_level", table_name="endpoints")
    op.drop_index("ix_endpoints_status", table_name="endpoints")
    op.drop_index("ix_endpoints_ip_address", table_name="endpoints")
    op.drop_index("ix_endpoints_hostname", table_name="endpoints")
    op.drop_table("endpoints")
