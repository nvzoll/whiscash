"""refresh token expires_at index

Revision ID: 003_refresh_token_expires_at_idx
Revises: 002_refresh_token_family
Create Date: 2026-08-26 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op

revision: str = "003_refresh_token_expires_at_idx"
down_revision: str | Sequence[str] | None = "002_refresh_token_family"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_index(
        op.f("refresh_token_expires_at_idx"),
        "refresh_token",
        ["expires_at"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("refresh_token_expires_at_idx"), table_name="refresh_token")
