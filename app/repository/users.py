from typing import Self
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import User
from app.db.session import SessionDependency
from app.repository.protocols import UserRepo


class DuplicateEmailError(Exception): ...


class SqlUserRepo:
    def __init__(self: Self, session: AsyncSession) -> None:
        self._session = session

    @classmethod
    async def new(
        cls: type[Self],
        session: SessionDependency,
    ) -> UserRepo:
        return cls(session)

    async def get_by_id(self, user_id: UUID) -> User | None:
        return await self._session.get(User, user_id)

    async def get_by_email(self, email: str) -> User | None:
        return await self._session.scalar(select(User).where(User.email == email))

    async def add(self, user: User) -> None:
        self._session.add(user)
        try:
            await self._session.flush()
        except IntegrityError as error:
            raise DuplicateEmailError from error

    async def save(self, user: User) -> None:
        await self._session.flush()
        await self._session.refresh(user)
