"""add sigma detection metadata columns

Revision ID: 36887004e260
Revises: 4e308c45e9a5
Create Date: 2026-07-21 09:00:00

Additive-only change for Part 8 — Sigma Rule Detection Engine: adds
matched_fields (JSONB), rule_category, and rule_tags (JSONB) to
sigma_detections, an index on rule_category, and a unique constraint on
(parsed_log_id, matched_rule) to prevent duplicate detections when a log
is re-scanned against the same rule. No existing column is renamed,
retyped, or dropped.
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "36887004e260"
down_revision: Union[str, None] = "4e308c45e9a5"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column("sigma_detections", sa.Column("matched_fields", postgresql.JSONB(), nullable=True))
    op.add_column("sigma_detections", sa.Column("rule_category", sa.String(50), nullable=True))
    op.add_column("sigma_detections", sa.Column("rule_tags", postgresql.JSONB(), nullable=True))
    op.create_index("ix_sigma_detections_rule_category", "sigma_detections", ["rule_category"])
    op.create_unique_constraint(
        "uq_sigma_detections_parsed_log_rule",
        "sigma_detections",
        ["parsed_log_id", "matched_rule"],
    )


def downgrade() -> None:
    op.drop_constraint(
        "uq_sigma_detections_parsed_log_rule", "sigma_detections", type_="unique"
    )
    op.drop_index("ix_sigma_detections_rule_category", table_name="sigma_detections")
    op.drop_column("sigma_detections", "rule_tags")
    op.drop_column("sigma_detections", "rule_category")
    op.drop_column("sigma_detections", "matched_fields")
