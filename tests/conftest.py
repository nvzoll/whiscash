import asyncio
import os
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from datetime import UTC, datetime, timedelta

os.environ.setdefault("JWT_SECRET", "unit-test-secret-change-me-32-bytes")
os.environ.setdefault("REFRESH_TOKEN_KEY", "PEeqpiAF7QRc9En7kJBm1VpRUX4UCCiOroUIBvn6GhU=")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://auth:auth@localhost:5432/auth")

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from testcontainers.community.postgres import PostgresContainer

from app.core.config import settings
from app.core.main import app
from app.db import session as db_session
from app.db.models import RefreshToken, User
from app.repository.protocols import RefreshTokenRepo, UserRepo
from app.repository.refresh_tokens import SqlRefreshTokenRepo
from app.repository.users import SqlUserRepo
from app.service.password import PasswordService
from tests.backends_postgres import (
    AutoCommitRefreshTokenRepo,
    AutoCommitUserRepo,
    async_url,
    run_migrations,
    start_container,
    truncate_all,
)
from tests.mocks import MockRefreshTokenRepo, MockStore, MockUserRepo


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--db-backend",
        action="store",
        default="mock",
        choices=["mock", "postgres"],
        help="Repository backend to run the suite against.",
    )


@pytest.fixture(scope="session")
def db_backend(request: pytest.FixtureRequest) -> str:
    return request.config.getoption("--db-backend")


@pytest.fixture(scope="session")
def postgres_container(db_backend: str) -> Iterator[PostgresContainer | None]:
    if db_backend != "postgres":
        yield None
        return

    container = start_container()
    try:
        run_migrations(async_url(container))
        yield container
    finally:
        container.stop()


@pytest.fixture(scope="session")
def pg_engine(postgres_container: PostgresContainer | None) -> Iterator[AsyncEngine | None]:
    if postgres_container is None:
        yield None
        return

    engine = create_async_engine(async_url(postgres_container), poolclass=NullPool)
    yield engine
    asyncio.run(engine.dispose())


@pytest.fixture
def mock_store() -> MockStore:
    return MockStore()


@pytest.fixture
async def pg_session(pg_engine: AsyncEngine | None) -> AsyncIterator[AsyncSession | None]:
    if pg_engine is None:
        yield None
        return

    session_factory = async_sessionmaker(pg_engine, expire_on_commit=False)
    async with session_factory() as session:
        yield session


@pytest.fixture
async def pg_cleanup(pg_session: AsyncSession | None) -> AsyncIterator[None]:
    yield
    if pg_session is not None:
        await truncate_all(pg_session)


@pytest.fixture
async def user_repo(
    db_backend: str,
    mock_store: MockStore,
    pg_session: AsyncSession | None,
    pg_cleanup: None,
) -> UserRepo:
    if db_backend == "postgres":
        assert pg_session is not None
        return AutoCommitUserRepo(pg_session)
    return MockUserRepo(mock_store)


@pytest.fixture
async def refresh_token_repo(
    db_backend: str,
    mock_store: MockStore,
    pg_session: AsyncSession | None,
    pg_cleanup: None,
) -> RefreshTokenRepo:
    if db_backend == "postgres":
        assert pg_session is not None
        return AutoCommitRefreshTokenRepo(pg_session)
    return MockRefreshTokenRepo(mock_store)


@pytest.fixture
async def make_refresh_token_repo(
    db_backend: str,
    mock_store: MockStore,
    pg_engine: AsyncEngine | None,
) -> AsyncIterator[Callable[[], Awaitable[RefreshTokenRepo]]]:
    sessions: list[AsyncSession] = []

    if db_backend == "postgres":
        assert pg_engine is not None
        session_factory = async_sessionmaker(pg_engine, expire_on_commit=False)

        async def factory() -> RefreshTokenRepo:
            session = session_factory()
            sessions.append(session)
            return AutoCommitRefreshTokenRepo(session)
    else:

        async def factory() -> RefreshTokenRepo:
            return MockRefreshTokenRepo(mock_store)

    yield factory

    for session in sessions:
        await session.close()


@pytest.fixture
def expire_refresh_reuse_grace(
    db_backend: str,
    mock_store: MockStore,
    pg_session: AsyncSession | None,
) -> Callable[[], Awaitable[None]]:
    async def expire_mock() -> None:
        past = datetime.now(UTC) - timedelta(seconds=settings.jwt_refresh_reuse_grace_seconds + 1)
        for token in mock_store.refresh_tokens.values():
            if token.revoked_at is not None:
                token.revoked_at = past

    async def expire_postgres() -> None:
        assert pg_session is not None
        past = datetime.now(UTC) - timedelta(seconds=settings.jwt_refresh_reuse_grace_seconds + 1)
        await pg_session.execute(update(RefreshToken).where(RefreshToken.revoked_at.is_not(None)).values(revoked_at=past))
        await pg_session.commit()

    return expire_postgres if db_backend == "postgres" else expire_mock


@pytest.fixture
async def seeded_user(user_repo: UserRepo) -> User:
    user = User(
        email="user@example.com",
        password_hash=PasswordService.hash("correct-horse"),
        email_verified=True,
    )
    await user_repo.add(user)
    return user


@pytest.fixture
async def client(
    db_backend: str,
    pg_engine: AsyncEngine | None,
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    seeded_user: User,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[AsyncClient]:
    if db_backend == "postgres":
        assert pg_engine is not None
        monkeypatch.setattr(db_session, "AsyncSessionLocal", async_sessionmaker(pg_engine, expire_on_commit=False))
    else:
        app.dependency_overrides[SqlUserRepo.new] = lambda: user_repo
        app.dependency_overrides[SqlRefreshTokenRepo.new] = lambda: refresh_token_repo

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client
    app.dependency_overrides.clear()
