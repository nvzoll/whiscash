"""refresh token family

Revision ID: 002_refresh_token_family
Revises: 001_initial
Create Date: 2026-08-25 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "002_refresh_token_family"
down_revision: str | Sequence[str] | None = "001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("refresh_token", sa.Column("family_id", sa.Uuid(), nullable=True))
    op.execute(sa.text("UPDATE refresh_token SET family_id = id"))
    op.alter_column("refresh_token", "family_id", nullable=False)
    op.create_index(
        op.f("refresh_token_family_id_idx"),
        "refresh_token",
        ["family_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("refresh_token_family_id_idx"), table_name="refresh_token")
    op.drop_column("refresh_token", "family_id")
