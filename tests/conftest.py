from __future__ import annotations

import os
from collections.abc import AsyncIterator

os.environ.setdefault("JWT_SECRET", "unit-test-secret-change-me-32-bytes")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://auth:auth@localhost:5432/auth")

import pytest
from httpx import ASGITransport, AsyncClient

from app.core.main import app
from app.db.models import User
from app.repository.refresh_tokens import SqlRefreshTokenRepo
from app.repository.users import SqlUserRepo
from app.service.password import PasswordService
from tests.mocks import MockRefreshTokenRepo, MockStore, MockUserRepo


@pytest.fixture
def mock_store() -> MockStore:
    return MockStore()


@pytest.fixture
async def seeded_user(mock_store: MockStore) -> User:
    user = User(
        email="user@example.com",
        password_hash=PasswordService.hash("correct-horse"),
        email_verified=True,
    )
    await MockUserRepo(mock_store).add(user)
    return user


@pytest.fixture
async def client(
    mock_store: MockStore,
    seeded_user: User,
) -> AsyncIterator[AsyncClient]:
    def get_user_repo_override() -> MockUserRepo:
        return MockUserRepo(mock_store)

    def get_refresh_token_repo_override() -> MockRefreshTokenRepo:
        return MockRefreshTokenRepo(mock_store)

    app.dependency_overrides[SqlUserRepo.new] = get_user_repo_override
    app.dependency_overrides[SqlRefreshTokenRepo.new] = get_refresh_token_repo_override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client
    app.dependency_overrides.clear()
