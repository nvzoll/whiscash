import asyncio
import os
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator
from datetime import UTC, datetime, timedelta
from uuid import UUID

os.environ.setdefault("JWT_SECRET", "unit-test-secret-change-me-32-bytes")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://auth:auth@localhost:5432/auth")
os.environ["LOGFIRE_TOKEN"] = ""

import pytest
from httpx import ASGITransport, AsyncClient
from redis.asyncio import Redis
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool
from testcontainers.community.postgres import PostgresContainer
from testcontainers.community.redis import RedisContainer

from app.cache.grace import RedisGraceCache
from app.cache.memory import InMemoryGraceCache
from app.cache.protocols import GraceCache
from app.core.config import settings
from app.core.main import app
from app.db import session as db_session
from app.db.models import PasswordResetToken, RefreshToken, ServiceClient, User
from app.repository.password_reset_tokens import SqlPasswordResetTokenRepo
from app.repository.protocols import PasswordResetTokenRepo, RefreshTokenRepo, ServiceClientRepo, UserRepo
from app.repository.refresh_tokens import SqlRefreshTokenRepo
from app.repository.service_clients import SqlServiceClientRepo
from app.repository.users import SqlUserRepo
from app.service.password import PasswordService
from app.service.service import AuthService
from tests.backends_postgres import (
    AutoCommitPasswordResetTokenRepo,
    AutoCommitRefreshTokenRepo,
    AutoCommitServiceClientRepo,
    AutoCommitUserRepo,
    async_url,
    run_migrations,
    start_container,
    truncate_all,
)
from tests.mocks import (
    MockPasswordResetTokenRepo,
    MockRefreshTokenRepo,
    MockServiceClientRepo,
    MockStore,
    MockUserRepo,
)
from tests.support import seed_service_client


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


@pytest.fixture(scope="session")
def redis_container(db_backend: str) -> Iterator[RedisContainer | None]:
    if db_backend != "postgres":
        yield None
        return

    container = RedisContainer()
    container.start()
    try:
        yield container
    finally:
        container.stop()


@pytest.fixture
async def redis_client(redis_container: RedisContainer | None) -> AsyncIterator[Redis | None]:
    if redis_container is None:
        yield None
        return

    client = Redis(
        host=redis_container.get_container_host_ip(),
        port=redis_container.get_exposed_port(redis_container.port),
        decode_responses=True,
    )
    try:
        yield client
    finally:
        await client.aclose()


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
async def password_reset_token_repo(
    db_backend: str,
    mock_store: MockStore,
    pg_session: AsyncSession | None,
    pg_cleanup: None,
) -> PasswordResetTokenRepo:
    if db_backend == "postgres":
        assert pg_session is not None
        return AutoCommitPasswordResetTokenRepo(pg_session)
    return MockPasswordResetTokenRepo(mock_store)


@pytest.fixture
async def service_client_repo(
    db_backend: str,
    mock_store: MockStore,
    pg_session: AsyncSession | None,
    pg_cleanup: None,
) -> ServiceClientRepo:
    if db_backend == "postgres":
        assert pg_session is not None
        return AutoCommitServiceClientRepo(pg_session)
    return MockServiceClientRepo(mock_store)


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
        await pg_session.execute(
            update(RefreshToken).where(RefreshToken.revoked_at.is_not(None)).values(revoked_at=past)
        )
        await pg_session.commit()

    return expire_postgres if db_backend == "postgres" else expire_mock


@pytest.fixture
def expire_password_reset_token(
    db_backend: str,
    mock_store: MockStore,
    pg_session: AsyncSession | None,
) -> Callable[[UUID], Awaitable[None]]:
    async def expire_mock(token_id: UUID) -> None:
        mock_store.password_reset_tokens[token_id].expires_at = datetime.now(UTC) - timedelta(seconds=1)

    async def expire_postgres(token_id: UUID) -> None:
        assert pg_session is not None
        await pg_session.execute(
            update(PasswordResetToken)
            .where(PasswordResetToken.id == token_id)
            .values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
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
async def seeded_service_client(service_client_repo: ServiceClientRepo) -> tuple[ServiceClient, str]:
    return await seed_service_client(service_client_repo)


@pytest.fixture
async def revoked_service_client(service_client_repo: ServiceClientRepo) -> tuple[ServiceClient, str]:
    return await seed_service_client(service_client_repo, name="revoked-consumer", revoked=True)


@pytest.fixture
async def unverified_user(user_repo: UserRepo) -> User:
    user = User(
        email="unverified@example.com",
        password_hash=PasswordService.hash("correct-horse"),
        email_verified=False,
    )
    await user_repo.add(user)
    return user


@pytest.fixture
async def grace_cache(
    db_backend: str,
    redis_client: Redis | None,
) -> AsyncIterator[GraceCache]:
    if db_backend == "postgres":
        assert redis_client is not None
        await redis_client.flushdb()
        yield RedisGraceCache(redis_client)
    else:
        yield InMemoryGraceCache()


@pytest.fixture
def auth_service(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    grace_cache: GraceCache,
) -> AuthService:
    return AuthService(
        user_repo,
        refresh_token_repo,
        password_reset_token_repo,
        service_client_repo,
        grace_cache,
    )


@pytest.fixture
async def client(
    db_backend: str,
    pg_engine: AsyncEngine | None,
    redis_client: Redis | None,
    grace_cache: GraceCache,
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    seeded_user: User,
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[AsyncClient]:
    if db_backend == "postgres":
        assert pg_engine is not None
        assert redis_client is not None
        monkeypatch.setattr(db_session, "AsyncSessionLocal", async_sessionmaker(pg_engine, expire_on_commit=False))
        app.dependency_overrides[RedisGraceCache.new] = lambda: RedisGraceCache(redis_client)
    else:
        app.dependency_overrides[SqlUserRepo.new] = lambda: user_repo
        app.dependency_overrides[SqlRefreshTokenRepo.new] = lambda: refresh_token_repo
        app.dependency_overrides[SqlPasswordResetTokenRepo.new] = lambda: password_reset_token_repo
        app.dependency_overrides[SqlServiceClientRepo.new] = lambda: service_client_repo
        app.dependency_overrides[RedisGraceCache.new] = lambda: grace_cache

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client
    app.dependency_overrides.clear()
