from typing import Self

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import ServiceClient
from app.db.session import SessionDependency
from app.repository.protocols import ServiceClientRepo


class SqlServiceClientRepo:
    def __init__(self: Self, session: AsyncSession) -> None:
        self._session = session

    @classmethod
    async def new(cls: type[Self], session: SessionDependency) -> ServiceClientRepo:
        return cls(session)

    async def get_by_key_hash(self, key_hash: str) -> ServiceClient | None:
        return await self._session.scalar(select(ServiceClient).where(ServiceClient.key_hash == key_hash))

    async def add(self, client: ServiceClient) -> None:
        self._session.add(client)
        await self._session.flush()
