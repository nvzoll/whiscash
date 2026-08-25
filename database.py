import os

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

database_url = os.environ["DATABASE_URL"]
engine = create_async_engine(database_url)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
