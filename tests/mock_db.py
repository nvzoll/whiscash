from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import Select
from sqlalchemy.exc import IntegrityError

from models import RefreshToken, User


class MockStore:
    def __init__(self) -> None:
        self.users: dict[UUID, User] = {}
        self.refresh_tokens: dict[UUID, RefreshToken] = {}
        self.emails: dict[str, UUID] = {}


class MockSession:
    def __init__(self, store: MockStore) -> None:
        self._store = store
        self._new: list[Any] = []

    async def __aenter__(self) -> MockSession:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    def add(self, instance: Any) -> None:
        self._new.append(instance)

    async def flush(self) -> None:
        for instance in self._new:
            if isinstance(instance, User):
                if instance.id is None:
                    instance.id = uuid4()
                if instance.email in self._store.emails:
                    raise IntegrityError(
                        statement="INSERT",
                        params={},
                        orig=Exception("duplicate email"),
                    )
                if instance.created_at is None:
                    instance.created_at = datetime.now(timezone.utc)
                self._store.users[instance.id] = instance
                self._store.emails[instance.email] = instance.id
            elif isinstance(instance, RefreshToken):
                if instance.id is None:
                    instance.id = uuid4()
                if instance.created_at is None:
                    instance.created_at = datetime.now(timezone.utc)
                self._store.refresh_tokens[instance.id] = instance
        self._new.clear()

    async def commit(self) -> None:
        await self.flush()

    async def refresh(self, instance: Any) -> None:
        if isinstance(instance, User) and instance.id in self._store.users:
            stored = self._store.users[instance.id]
            instance.created_at = stored.created_at

    async def rollback(self) -> None:
        self._new.clear()

    async def get(self, model: type, entity_id: UUID) -> Any | None:
        if model is User:
            return self._store.users.get(entity_id)
        if model is RefreshToken:
            return self._store.refresh_tokens.get(entity_id)
        return None

    async def scalar(self, statement: Select[Any]) -> Any | None:
        if not isinstance(statement, Select):
            return None
        descriptions = statement.column_descriptions
        if not descriptions or descriptions[0].get("entity") is not User:
            return None
        email = _extract_email_filter(statement)
        if email is None:
            return None
        user_id = self._store.emails.get(email)
        if user_id is None:
            return None
        return self._store.users.get(user_id)


class MockSessionFactory:
    def __init__(self, store: MockStore) -> None:
        self._store = store

    def __call__(self) -> MockSession:
        return MockSession(self._store)


def _extract_email_filter(statement: Select[Any]) -> str | None:
    where = statement.whereclause
    if where is None:
        return None
    email = _email_from_clause(where)
    if email is not None:
        return email
    for child in where.get_children():
        email = _email_from_clause(child)
        if email is not None:
            return email
    return None


def _email_from_clause(clause: Any) -> str | None:
    left = getattr(clause, "left", None)
    if getattr(left, "key", None) != "email":
        return None
    right = clause.right
    if hasattr(right, "value"):
        return str(right.value)
    return str(right)


async def override_get_session(store: MockStore) -> AsyncIterator[MockSession]:
    session = MockSession(store)
    yield session
