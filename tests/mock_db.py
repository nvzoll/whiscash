from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timezone
from typing import Any, Self, cast
from uuid import UUID, uuid4

from sqlalchemy import Select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

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

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    def add(self, instance: Any) -> None:
        self._new.append(instance)

    async def flush(self) -> None:
        for instance in self._new:
            if isinstance(instance, User):
                _set_insert_defaults(instance)
                if instance.email in self._store.emails:
                    raise IntegrityError(
                        statement="INSERT",
                        params={},
                        orig=Exception("duplicate email"),
                    )
                self._store.users[instance.id] = instance
                self._store.emails[instance.email] = instance.id
            elif isinstance(instance, RefreshToken):
                _set_insert_defaults(instance)
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

    async def get[T](self, model: type[T], entity_id: UUID) -> T | None:
        stored: object | None
        if model is User:
            stored = self._store.users.get(entity_id)
        elif model is RefreshToken:
            stored = self._store.refresh_tokens.get(entity_id)
        else:
            return None
        return stored if isinstance(stored, model) else None

    async def scalar(self, statement: Select[Any]) -> Any | None:
        if not isinstance(statement, Select):
            return None
        descriptions = statement.column_descriptions
        if not descriptions or descriptions[0].get("entity") is not User:
            return None
        if not (email := _extract_email_filter(statement)):
            return None
        if not (user_id := self._store.emails.get(email)):
            return None
        return self._store.users.get(user_id)


class MockSessionFactory:
    def __init__(self, store: MockStore) -> None:
        self._store = store

    def __call__(self) -> AsyncSession:
        return cast(AsyncSession, MockSession(self._store))


def _set_insert_defaults(instance: User | RefreshToken) -> None:
    if "id" not in instance.__dict__:
        instance.id = uuid4()
    if "created_at" not in instance.__dict__:
        instance.created_at = datetime.now(timezone.utc)


def _extract_email_filter(statement: Select[Any]) -> str | None:
    where = statement.whereclause
    if where is None:
        return None
    for clause in (where, *where.get_children()):
        if email := _email_from_clause(clause):
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


async def override_get_session(store: MockStore) -> AsyncIterator[AsyncSession]:
    yield cast(AsyncSession, MockSession(store))
