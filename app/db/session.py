from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, HTTPException
from sqlalchemy.exc import PendingRollbackError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from app.core.config import settings

engine = create_async_engine(settings.database_url)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except HTTPException:
            try:
                await session.commit()
            except PendingRollbackError:
                await session.rollback()
            raise
        except Exception:
            await session.rollback()
            raise
        else:
            await session.commit()


SessionDependency = Annotated[AsyncSession, Depends(get_session, scope="function")]
