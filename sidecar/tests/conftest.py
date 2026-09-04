import asyncio
import os

os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://auth:auth@localhost:5432/auth")

import subprocess
from collections.abc import AsyncIterator, Iterator
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool
from testcontainers.community.postgres import PostgresContainer

REPO_ROOT = Path(__file__).resolve().parents[2]


def start_container() -> PostgresContainer:
    container = PostgresContainer("postgres:16-alpine", driver="asyncpg")
    container.start()
    return container


def async_url(container: PostgresContainer) -> str:
    return container.get_connection_url()


def run_migrations(database_url: str) -> None:
    subprocess.run(
        ["uv", "run", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env={
            **os.environ,
            "DATABASE_URL": database_url,
            "JWT_SECRET": os.environ.get("JWT_SECRET", "test-secret"),
            "REDIS_URL": os.environ.get("REDIS_URL", "redis://localhost:6379/0"),
        },
        check=True,
    )


@pytest.fixture(scope="session")
def postgres_container() -> Iterator[PostgresContainer]:
    container = start_container()
    try:
        url = async_url(container)
        run_migrations(url)
        yield container
    finally:
        container.stop()


@pytest.fixture(scope="session")
def database_url(postgres_container: PostgresContainer) -> str:
    return async_url(postgres_container)


@pytest.fixture(scope="session")
def engine(database_url: str) -> Iterator[AsyncEngine]:
    eng = create_async_engine(database_url, poolclass=NullPool)
    yield eng
    asyncio.run(eng.dispose())


@pytest.fixture
async def conn(engine: AsyncEngine) -> AsyncIterator[AsyncConnection]:
    async with engine.connect() as connection:
        await connection.execute(
            text('TRUNCATE TABLE password_reset_token, refresh_token, "user" RESTART IDENTITY CASCADE')
        )
        await connection.commit()
        yield connection


async def insert_user(conn: AsyncConnection, *, user_id: str | None = None) -> str:
    uid = user_id or str(uuid4())
    await conn.execute(
        text(
            'INSERT INTO "user" (id, email, password_hash) '
            'VALUES (:id, :email, :password_hash)'
        ),
        {
            "id": uid,
            "email": f"{uid}@example.com",
            "password_hash": "hash",
        },
    )
    await conn.commit()
    return uid
