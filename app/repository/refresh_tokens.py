from datetime import UTC, datetime
from typing import Self
from uuid import UUID

from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import RefreshToken
from app.db.session import SessionDependency
from app.repository.protocols import RefreshTokenRepo


class SqlRefreshTokenRepo:
    def __init__(self: Self, session: AsyncSession) -> None:
        self._session = session

    @classmethod
    async def new(cls: type[Self], session: SessionDependency) -> RefreshTokenRepo:
        return cls(session)

    async def get_by_id(self, token_id: UUID, *, for_update: bool = False) -> RefreshToken | None:
        return await self._session.get(
            RefreshToken,
            token_id,
            with_for_update=for_update,
            populate_existing=True,
        )

    async def add(self, refresh_token: RefreshToken) -> None:
        self._session.add(refresh_token)
        await self._session.flush()

    async def revoke(
        self,
        refresh_token: RefreshToken,
        *,
        replaced_by: UUID | None = None,
        replacement_secret: str | None = None,
    ) -> bool:
        now = datetime.now(UTC)
        values: dict[str, object] = {"revoked_at": now}
        if replaced_by is not None:
            values["replaced_by"] = replaced_by
            values["replacement_secret"] = replacement_secret

        result = await self._session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.id == refresh_token.id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(**values)
            .returning(RefreshToken.id)
        )
        if result.scalar_one_or_none() is None:
            return False

        refresh_token.revoked_at = now
        if replaced_by is not None:
            refresh_token.replaced_by = replaced_by
            refresh_token.replacement_secret = replacement_secret

        return True

    async def revoke_family(self, *, user_id: UUID, family_id: UUID) -> None:
        now = datetime.now(UTC)
        await self._session.execute(
            update(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.family_id == family_id,
                RefreshToken.revoked_at.is_(None),
            )
            .values(revoked_at=now)
        )
