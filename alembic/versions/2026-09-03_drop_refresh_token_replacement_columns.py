"""drop refresh token replacement columns

Revision ID: 003_drop_replacement_columns
Revises: 002_password_reset
Create Date: 2026-09-03 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "003_drop_replacement_columns"
down_revision: str | Sequence[str] | None = "002_password_reset"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_constraint(op.f("refresh_token_replaced_by_fkey"), "refresh_token", type_="foreignkey")
    op.drop_column("refresh_token", "replaced_by")
    op.drop_column("refresh_token", "replacement_secret")


def downgrade() -> None:
    op.add_column("refresh_token", sa.Column("replacement_secret", sa.String(length=256), nullable=True))
    op.add_column("refresh_token", sa.Column("replaced_by", sa.Uuid(), nullable=True))
    op.create_foreign_key(
        op.f("refresh_token_replaced_by_fkey"),
        "refresh_token",
        "refresh_token",
        ["replaced_by"],
        ["id"],
        ondelete="SET NULL",
    )
