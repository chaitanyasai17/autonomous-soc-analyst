"""add resolved_ip, informational_count, and exposed_services to web_security_scans

Revision ID: b2c3d4e5f6a7
Revises: a1b2c3d4e5f6
Create Date: 2026-09-11 11:00:00

Additive migration:
- Adds resolved_ip column to web_security_scans
- Adds informational_count column to web_security_scans
- Adds exposed_services column to web_security_scans
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "b2c3d4e5f6a7"
down_revision: Union[str, None] = "a1b2c3d4e5f6"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("web_security_scans", sa.Column("resolved_ip", sa.String(255), nullable=True))
    op.add_column("web_security_scans", sa.Column("informational_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("web_security_scans", sa.Column("exposed_services", postgresql.JSONB(), nullable=True))


def downgrade() -> None:
    op.drop_column("web_security_scans", "exposed_services")
    op.drop_column("web_security_scans", "informational_count")
    op.drop_column("web_security_scans", "resolved_ip")
