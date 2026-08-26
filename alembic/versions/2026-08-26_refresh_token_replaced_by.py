"""refresh token replaced_by_token

Revision ID: 004_refresh_token_replaced_by
Revises: 003_refresh_token_expires_at_idx
Create Date: 2026-08-26 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "004_refresh_token_replaced_by"
down_revision: str | Sequence[str] | None = "003_refresh_token_expires_at_idx"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "refresh_token",
        sa.Column("replaced_by_token", sa.String(length=128), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("refresh_token", "replaced_by_token")
