from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.db.models import RefreshToken, User
from app.repository.users import DuplicateEmailError


@dataclass
class FakeStore:
    users: dict[UUID, User] = field(default_factory=dict)
    emails: dict[str, UUID] = field(default_factory=dict)
    refresh_tokens: dict[UUID, RefreshToken] = field(default_factory=dict)
    revoke_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class FakeUserRepo:
    def __init__(self, store: FakeStore) -> None:
        self._store = store

    async def get_by_id(self, user_id: UUID) -> User | None:
        return self._store.users.get(user_id)

    async def get_by_email(self, email: str) -> User | None:
        user_id = self._store.emails.get(email)
        if user_id is None:
            return None
        return self._store.users.get(user_id)

    async def add(self, user: User) -> None:
        if user.email in self._store.emails:
            raise DuplicateEmailError
        if user.id is None:
            user.id = uuid4()
        user.created_at = datetime.now(UTC)
        self._store.users[user.id] = user
        self._store.emails[user.email] = user.id

    async def save(self, user: User) -> None:
        self._store.users[user.id] = user


class FakeRefreshTokenRepo:
    def __init__(self, store: FakeStore) -> None:
        self._store = store

    async def get_by_id(
        self,
        token_id: UUID,
        *,
        for_update: bool = False,
    ) -> RefreshToken | None:
        return self._store.refresh_tokens.get(token_id)

    async def add(self, refresh_token: RefreshToken) -> None:
        self._store.refresh_tokens[refresh_token.id] = refresh_token

    async def revoke(self, refresh_token: RefreshToken) -> bool:
        async with self._store.revoke_lock:
            stored = self._store.refresh_tokens.get(refresh_token.id)
            if stored is None or stored.revoked_at is not None:
                return False
            now = datetime.now(UTC)
            stored.revoked_at = now
            refresh_token.revoked_at = now
            return True

    def seed_session(self, user: User) -> UUID:
        token_id = uuid4()
        refresh_token = RefreshToken(
            id=token_id,
            user_id=user.id,
            token_hash="test-token-hash",
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )
        self._store.refresh_tokens[token_id] = refresh_token
        return token_id
