from datetime import UTC, datetime
from typing import Self
from uuid import UUID

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import PasswordResetToken
from app.db.session import SessionDependency
from app.repository.protocols import PasswordResetTokenRepo


class SqlPasswordResetTokenRepo:
    def __init__(self: Self, session: AsyncSession) -> None:
        self._session = session

    @classmethod
    async def new(cls: type[Self], session: SessionDependency) -> PasswordResetTokenRepo:
        return cls(session)

    async def get_by_id(self, token_id: UUID, *, for_update: bool = False) -> PasswordResetToken | None:
        return await self._session.get(
            PasswordResetToken,
            token_id,
            with_for_update=for_update,
            populate_existing=True,
        )

    async def add(self, token: PasswordResetToken) -> None:
        self._session.add(token)
        await self._session.flush()

    async def mark_used(self, token: PasswordResetToken) -> bool:
        now = datetime.now(UTC)
        result = await self._session.execute(
            update(PasswordResetToken)
            .where(
                PasswordResetToken.id == token.id,
                PasswordResetToken.used_at.is_(None),
            )
            .values(used_at=now)
            .returning(PasswordResetToken.id)
        )
        if result.scalar_one_or_none() is None:
            return False

        token.used_at = now

        return True
