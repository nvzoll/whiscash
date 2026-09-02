"""password reset tokens and service clients

Revision ID: 002_password_reset
Revises: 001_initial
Create Date: 2026-09-02 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "002_password_reset"
down_revision: str | Sequence[str] | None = "001_initial"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "password_reset_token",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["user.id"],
            name=op.f("password_reset_token_user_id_fkey"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("password_reset_token_pkey")),
    )
    op.create_index(
        op.f("password_reset_token_user_id_idx"),
        "password_reset_token",
        ["user_id"],
        unique=False,
    )
    op.create_index(
        op.f("password_reset_token_expires_at_idx"),
        "password_reset_token",
        ["expires_at"],
        unique=False,
    )
    op.create_table(
        "service_client",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("key_hash", sa.String(length=64), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("service_client_pkey")),
    )
    op.create_index(
        op.f("service_client_key_hash_idx"),
        "service_client",
        ["key_hash"],
        unique=True,
    )


def downgrade() -> None:
    op.drop_index(op.f("service_client_key_hash_idx"), table_name="service_client")
    op.drop_table("service_client")
    op.drop_index(op.f("password_reset_token_expires_at_idx"), table_name="password_reset_token")
    op.drop_index(op.f("password_reset_token_user_id_idx"), table_name="password_reset_token")
    op.drop_table("password_reset_token")
