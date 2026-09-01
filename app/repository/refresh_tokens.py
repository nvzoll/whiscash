from datetime import UTC, datetime
from typing import Annotated, Self
from uuid import UUID

from fastapi import Depends
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import RefreshToken
from app.db.session import get_session
from app.repository.protocols import RefreshTokenRepo


class SqlRefreshTokenRepo:
    def __init__(self: Self, session: AsyncSession) -> None:
        self._session = session

    @classmethod
    async def new(
        cls: type[Self],
        session: Annotated[AsyncSession, Depends(get_session)],
    ) -> RefreshTokenRepo:
        return cls(session)

    async def get_by_id(
        self,
        token_id: UUID,
        *,
        for_update: bool = False,
    ) -> RefreshToken | None:
        return await self._session.get(
            RefreshToken,
            token_id,
            with_for_update=for_update,
            populate_existing=True,
        )

    async def add(self, refresh_token: RefreshToken) -> None:
        self._session.add(refresh_token)
        await self._session.flush()

    async def revoke(self, refresh_token: RefreshToken) -> bool:
        now = datetime.now(UTC)
        result = await self._session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.id == refresh_token.id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
            .returning(RefreshToken.id)
        )
        if result.scalar_one_or_none() is None:
            return False

        refresh_token.revoked_at = now

        return True
