from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.db.models import RefreshToken, User
from app.repository.users import DuplicateEmailError


@dataclass
class MockStore:
    users: dict[UUID, User] = field(default_factory=dict)
    emails: dict[str, UUID] = field(default_factory=dict)
    refresh_tokens: dict[UUID, RefreshToken] = field(default_factory=dict)
    revoke_lock: asyncio.Lock = field(default_factory=asyncio.Lock)


class MockUserRepo:
    def __init__(self, store: MockStore) -> None:
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


class MockRefreshTokenRepo:
    def __init__(self, store: MockStore) -> None:
        self._store = store

    async def get_by_id(
        self,
        token_id: UUID,
        *,
        for_update: bool = False,
    ) -> RefreshToken | None:
        return self._store.refresh_tokens.get(token_id)

    async def add(self, refresh_token: RefreshToken) -> None:
        if refresh_token.family_id is None:
            refresh_token.family_id = uuid4()
        if refresh_token.created_at is None:
            refresh_token.created_at = datetime.now(UTC)
        self._store.refresh_tokens[refresh_token.id] = refresh_token

    async def revoke(
        self,
        refresh_token: RefreshToken,
        *,
        replaced_by: UUID | None = None,
        replacement_secret: str | None = None,
    ) -> bool:
        async with self._store.revoke_lock:
            stored = self._store.refresh_tokens.get(refresh_token.id)
            if stored is None or stored.revoked_at is not None:
                return False
            now = datetime.now(UTC)
            stored.revoked_at = now
            refresh_token.revoked_at = now
            if replaced_by is not None:
                stored.replaced_by = replaced_by
                stored.replacement_secret = replacement_secret
                refresh_token.replaced_by = replaced_by
                refresh_token.replacement_secret = replacement_secret
            return True

    async def revoke_family(self, *, user_id: UUID, family_id: UUID) -> None:
        now = datetime.now(UTC)
        for token in self._store.refresh_tokens.values():
            if token.user_id == user_id and token.family_id == family_id and token.revoked_at is None:
                token.revoked_at = now

    def seed_session(self, user: User) -> UUID:
        token_id = uuid4()
        refresh_token = RefreshToken(
            id=token_id,
            user_id=user.id,
            family_id=uuid4(),
            token_hash="test-token-hash",
            expires_at=datetime.now(UTC) + timedelta(days=30),
            created_at=datetime.now(UTC),
        )
        self._store.refresh_tokens[token_id] = refresh_token
        return token_id
