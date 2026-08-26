"""drop plaintext successor refresh token

Revision ID: 005_refresh_token_replaced_by_id
Revises: 004_refresh_token_replaced_by
Create Date: 2026-08-26 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "005_refresh_token_replaced_by_id"
down_revision: str | Sequence[str] | None = "004_refresh_token_replaced_by"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("refresh_token", "replaced_by_token")
    op.add_column("refresh_token", sa.Column("replaced_by_id", sa.Uuid(), nullable=True))
    op.create_index(
        op.f("refresh_token_replaced_by_id_idx"),
        "refresh_token",
        ["replaced_by_id"],
        unique=False,
    )
    op.create_foreign_key(
        op.f("refresh_token_replaced_by_id_fkey"),
        "refresh_token",
        "refresh_token",
        ["replaced_by_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    op.drop_constraint(
        op.f("refresh_token_replaced_by_id_fkey"),
        "refresh_token",
        type_="foreignkey",
    )
    op.drop_index(op.f("refresh_token_replaced_by_id_idx"), table_name="refresh_token")
    op.drop_column("refresh_token", "replaced_by_id")
    op.add_column(
        "refresh_token",
        sa.Column("replaced_by_token", sa.String(length=128), nullable=True),
    )
