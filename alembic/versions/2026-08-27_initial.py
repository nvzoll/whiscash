"""initial

Revision ID: 001_initial
Revises:
Create Date: 2026-08-27 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "001_initial"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "user",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=320), nullable=False),
        sa.Column("password_hash", sa.String(length=60), nullable=False),
        sa.Column("display_name", sa.String(length=128), nullable=True),
        sa.Column("photo_url", sa.String(length=2048), nullable=True),
        sa.Column(
            "email_verified",
            sa.Boolean(),
            server_default=sa.false(),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("user_pkey")),
    )
    op.create_index(op.f("user_email_idx"), "user", ["email"], unique=True)
    op.create_table(
        "refresh_token",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("family_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("replaced_by", sa.Uuid(), nullable=True),
        sa.Column("replacement_secret", sa.String(length=256), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("refresh_token_user_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["replaced_by"],
            ["refresh_token.id"],
            name=op.f("refresh_token_replaced_by_fkey"),
            ondelete="SET NULL",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("refresh_token_pkey")),
    )
    op.create_index(
        op.f("refresh_token_user_id_idx"),
        "refresh_token",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        op.f("refresh_token_expires_at_idx"),
        "refresh_token",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f("refresh_token_family_id_idx"),
        "refresh_token",
        ["family_id"],
        unique=False,
    )


def downgrade() -> None:
    op.drop_index(op.f("refresh_token_family_id_idx"), table_name="refresh_token")
    op.drop_index(op.f("refresh_token_expires_at_idx"), table_name="refresh_token")
    op.drop_index(op.f("refresh_token_user_id_idx"), table_name="refresh_token")
    op.drop_table("refresh_token")
    op.drop_index(op.f("user_email_idx"), table_name="user")
    op.drop_table("user")
