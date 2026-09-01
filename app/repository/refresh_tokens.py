from datetime import UTC, datetime
from uuid import UUID

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import RefreshToken


class SqlRefreshTokenRepo:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

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
