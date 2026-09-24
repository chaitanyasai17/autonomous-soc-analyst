"""add normalization columns to parsed_logs

Revision ID: 4e308c45e9a5
Revises: 6b86e91905d2
Create Date: 2026-07-19 09:00:00

Additive-only change for Part 6 — Log Parser Engine: adds source_port,
destination_port, protocol, action, message, and event_id to parsed_logs,
plus an index on action. No existing column is renamed, retyped, or
dropped. All new columns are nullable, since not every log format
populates every normalized field (see Part 6 "Handle missing fields
gracefully" requirement).
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = "4e308c45e9a5"
down_revision: Union[str, None] = "6b86e91905d2"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("parsed_logs", sa.Column("source_port", sa.Integer(), nullable=True))
    op.add_column("parsed_logs", sa.Column("destination_port", sa.Integer(), nullable=True))
    op.add_column("parsed_logs", sa.Column("protocol", sa.String(20), nullable=True))
    op.add_column("parsed_logs", sa.Column("action", sa.String(50), nullable=True))
    op.add_column("parsed_logs", sa.Column("message", sa.Text(), nullable=True))
    op.add_column("parsed_logs", sa.Column("event_id", sa.String(100), nullable=True))
    op.create_index("ix_parsed_logs_action", "parsed_logs", ["action"])


def downgrade() -> None:
    op.drop_index("ix_parsed_logs_action", table_name="parsed_logs")
    op.drop_column("parsed_logs", "event_id")
    op.drop_column("parsed_logs", "message")
    op.drop_column("parsed_logs", "action")
    op.drop_column("parsed_logs", "protocol")
    op.drop_column("parsed_logs", "destination_port")
    op.drop_column("parsed_logs", "source_port")
