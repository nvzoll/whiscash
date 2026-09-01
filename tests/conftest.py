from __future__ import annotations

import os
from collections.abc import AsyncIterator

os.environ.setdefault("JWT_SECRET", "unit-test-secret-change-me-32-bytes")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://auth:auth@localhost:5432/auth")

import pytest
from httpx import ASGITransport, AsyncClient

from app.controller.deps import get_refresh_token_repo, get_user_repo
from app.core.main import app
from app.db.models import User
from app.service.password import hash_password
from tests.fakes import FakeRefreshTokenRepo, FakeStore, FakeUserRepo


@pytest.fixture
def fake_store() -> FakeStore:
    return FakeStore()


@pytest.fixture
async def seeded_user(fake_store: FakeStore) -> User:
    user = User(
        email="user@example.com",
        password_hash=hash_password("correct-horse"),
        email_verified=True,
    )
    await FakeUserRepo(fake_store).add(user)
    return user


@pytest.fixture
async def client(
    fake_store: FakeStore,
    seeded_user: User,
) -> AsyncIterator[AsyncClient]:
    def get_user_repo_override() -> FakeUserRepo:
        return FakeUserRepo(fake_store)

    def get_refresh_token_repo_override() -> FakeRefreshTokenRepo:
        return FakeRefreshTokenRepo(fake_store)

    app.dependency_overrides[get_user_repo] = get_user_repo_override
    app.dependency_overrides[get_refresh_token_repo] = get_refresh_token_repo_override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as http_client:
        yield http_client
    app.dependency_overrides.clear()
