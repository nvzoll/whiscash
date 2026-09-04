"""partial index on password_reset_token used_at

Revision ID: 004_password_reset_used_at_idx
Revises: 003_drop_replacement_columns
Create Date: 2026-09-04 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "004_password_reset_used_at_idx"
down_revision: str | Sequence[str] | None = "003_drop_replacement_columns"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        "password_reset_token_used_at_idx",
        "password_reset_token",
        ["used_at"],
        postgresql_where=sa.text("used_at IS NOT NULL"),
    )


def downgrade() -> None:
    op.drop_index("password_reset_token_used_at_idx", table_name="password_reset_token")
