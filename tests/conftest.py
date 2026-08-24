from __future__ import annotations

import os
from collections.abc import AsyncIterator

os.environ.setdefault("JWT_SECRET", "unit-test-secret-change-me-32-bytes")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://auth:auth@localhost:5432/auth")

import pytest
from httpx import ASGITransport, AsyncClient

from main import app, get_session, hash_password
from models import User
from tests.mock_db import MockSessionFactory, MockStore, override_get_session


@pytest.fixture
def mock_store() -> MockStore:
    return MockStore()


@pytest.fixture
def session_factory(mock_store: MockStore) -> MockSessionFactory:
    return MockSessionFactory(mock_store)


@pytest.fixture
async def seeded_user(session_factory: MockSessionFactory) -> User:
    async with session_factory() as session:
        user = User(
            email="user@example.com",
            password_hash=hash_password("correct-horse"),
            email_verified=True,
        )
        session.add(user)
        await session.commit()
        await session.refresh(user)
        return user


@pytest.fixture
async def client(
    mock_store: MockStore,
    seeded_user: User,
) -> AsyncIterator[AsyncClient]:
    async def get_session_override() -> AsyncIterator:
        async for session in override_get_session(mock_store):
            yield session

    app.dependency_overrides[get_session] = get_session_override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client
    app.dependency_overrides.clear()
