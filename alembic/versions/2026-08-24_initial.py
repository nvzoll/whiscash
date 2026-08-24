"""initial

Revision ID: 001_initial
Revises:
Create Date: 2026-08-24 00:00:00.000000

"""

from collections.abc import Sequence

from alembic import op
from models import Base

revision: str = "001_initial"
down_revision: str | Sequence[str] | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    Base.metadata.create_all(bind=op.get_bind())


def downgrade() -> None:
    Base.metadata.drop_all(bind=op.get_bind())
