"""add super_admin to user_role enum

Revision ID: 63488162ea6a
Revises: 926b474f0a22
Create Date: 2026-07-17 09:00:00

Additive-only change: adds a new value to the existing native PostgreSQL
`user_role` enum type to support the 5-role RBAC model introduced in
Part 4 — Authentication & User Management (Super Admin, Admin, SOC Analyst,
Security Manager, Viewer). No existing values, tables, or columns change.

Note: PostgreSQL does not support removing enum values or running
`ALTER TYPE ... ADD VALUE` reversibly within the same transaction that
uses the new value, so `downgrade()` is intentionally a no-op with an
explanatory comment rather than attempting an unsafe reversal.
"""

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "63488162ea6a"
down_revision: Union[str, None] = "926b474f0a22"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.execute("ALTER TYPE user_role ADD VALUE IF NOT EXISTS 'super_admin'")


def downgrade() -> None:
    # PostgreSQL cannot drop a single enum value (would require rebuilding
    # the type and rewriting every dependent column). If this needs to be
    # reversed, do so manually via a new migration that recreates the enum
    # without 'super_admin' once no rows reference it.
    pass
