"""add upload metadata columns to security_logs

Revision ID: 6b86e91905d2
Revises: 63488162ea6a
Create Date: 2026-07-18 09:00:00

Additive-only change for Part 5 — Log Upload Module: adds file_size,
mime_type, storage_path, and checksum_sha256 to security_logs, plus an
index on checksum_sha256. No existing column is renamed, retyped, or
dropped. Assumes no pre-existing rows (true for this project's current
state) — NOT NULL is applied directly rather than via a two-step
backfill-then-constrain migration.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "6b86e91905d2"
down_revision: Union[str, None] = "63488162ea6a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("security_logs", sa.Column("file_size", sa.BigInteger(), nullable=False))
    op.add_column("security_logs", sa.Column("mime_type", sa.String(100), nullable=False))
    op.add_column("security_logs", sa.Column("storage_path", sa.String(500), nullable=False))
    op.add_column(
        "security_logs", sa.Column("checksum_sha256", sa.String(64), nullable=False)
    )
    op.create_index(
        "ix_security_logs_checksum_sha256", "security_logs", ["checksum_sha256"]
    )


def downgrade() -> None:
    op.drop_index("ix_security_logs_checksum_sha256", table_name="security_logs")
    op.drop_column("security_logs", "checksum_sha256")
    op.drop_column("security_logs", "storage_path")
    op.drop_column("security_logs", "mime_type")
    op.drop_column("security_logs", "file_size")
