from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import UTC, datetime
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

    async def get[T](self, model: type[T], entity_id: UUID, **_: Any) -> T | None:
        stored: object | None
        if model is User:
            stored = self._store.users.get(entity_id)
        elif model is RefreshToken:
            stored = self._store.refresh_tokens.get(entity_id)
        else:
            return None
        return stored if isinstance(stored, model) else None

    async def execute(self, statement: Any) -> MockResult:
        token_id, user_id, family_id, requires_active, values = (
            _parse_refresh_token_update(statement)
        )
        if token_id is None and family_id is None and user_id is None:
            return MockResult()
        updated_id: UUID | None = None
        for token in self._store.refresh_tokens.values():
            if token_id is not None and token.id != token_id:
                continue
            if user_id is not None and token.user_id != user_id:
                continue
            if family_id is not None and token.family_id != family_id:
                continue
            if requires_active and token.revoked_at is not None:
                continue
            for key, value in values.items():
                setattr(token, key, value)
            updated_id = token.id
        if updated_id is None:
            return MockResult()
        return MockResult(updated_id)

    async def scalar(self, statement: Select[Any]) -> Any | None:
        if not isinstance(statement, Select):
            return None
        descriptions = statement.column_descriptions
        if not descriptions:
            return None
        entity = descriptions[0].get("entity")
        if entity is User:
            if not (email := _extract_email_filter(statement)):
                return None
            if not (user_id := self._store.emails.get(email)):
                return None
            return self._store.users.get(user_id)
        if entity is RefreshToken:
            return _find_refresh_token(self._store, statement)
        return None


class MockResult:
    def __init__(self, value: UUID | None = None) -> None:
        self._value = value

    def scalar_one_or_none(self) -> UUID | None:
        return self._value


class MockSessionFactory:
    def __init__(self, store: MockStore) -> None:
        self._store = store

    def __call__(self) -> AsyncSession:
        return cast(AsyncSession, MockSession(self._store))


def _set_insert_defaults(instance: User | RefreshToken) -> None:
    if "id" not in instance.__dict__:
        instance.id = uuid4()
    if "created_at" not in instance.__dict__:
        instance.created_at = datetime.now(UTC)
    if isinstance(instance, RefreshToken) and "family_id" not in instance.__dict__:
        instance.family_id = uuid4()


def _find_refresh_token(store: MockStore, statement: Select[Any]) -> RefreshToken | None:
    where = statement.whereclause
    if where is None:
        return None
    user_id: UUID | None = None
    family_id: UUID | None = None
    requires_active = False
    for clause in _iter_where_clauses(where):
        if user_id is None:
            user_id = _uuid_from_clause(clause, "user_id")
        if family_id is None:
            family_id = _uuid_from_clause(clause, "family_id")
        if _is_null_clause(clause, "revoked_at"):
            requires_active = True
    matched: RefreshToken | None = None
    for token in store.refresh_tokens.values():
        if user_id is not None and token.user_id != user_id:
            continue
        if family_id is not None and token.family_id != family_id:
            continue
        if requires_active and token.revoked_at is not None:
            continue
        if _refresh_token_unexpired(token):
            return token
        if matched is None:
            matched = token
    return matched


def _refresh_token_unexpired(token: RefreshToken) -> bool:
    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at > datetime.now(UTC)


def _extract_email_filter(statement: Select[Any]) -> str | None:
    where = statement.whereclause
    if where is None:
        return None
    for clause in (where, *where.get_children()):
        if email := _email_from_clause(clause):
            return email
    return None


def _parse_refresh_token_update(
    statement: Any,
) -> tuple[UUID | None, UUID | None, UUID | None, bool, dict[str, Any]]:
    where = getattr(statement, "whereclause", None)
    if where is None:
        return None, None, None, False, {}
    token_id: UUID | None = None
    user_id: UUID | None = None
    family_id: UUID | None = None
    requires_active = False
    for clause in _iter_where_clauses(where):
        if token_id is None:
            token_id = _uuid_from_clause(clause, "id")
        if user_id is None:
            user_id = _uuid_from_clause(clause, "user_id")
        if family_id is None:
            family_id = _uuid_from_clause(clause, "family_id")
        if _is_null_clause(clause, "revoked_at"):
            requires_active = True
    values: dict[str, Any] = {}
    for column, value in getattr(statement, "_values", {}).items():
        key = getattr(column, "key", None)
        if key is None:
            continue
        values[key] = getattr(value, "value", value)
    return token_id, user_id, family_id, requires_active, values


def _iter_where_clauses(where: Any) -> list[Any]:
    if type(where).__name__ != "BooleanClauseList":
        return [where]
    clauses: list[Any] = []
    for child in getattr(where, "get_children", lambda: ())():
        clauses.extend(_iter_where_clauses(child))
    return clauses or [where]


def _uuid_from_clause(clause: Any, key: str) -> UUID | None:
    left = getattr(clause, "left", None)
    if getattr(left, "key", None) != key:
        return None
    right = getattr(clause, "right", None)
    value = getattr(right, "value", None)
    return value if isinstance(value, UUID) else None


def _is_null_clause(clause: Any, key: str) -> bool:
    left = getattr(clause, "left", None)
    if getattr(left, "key", None) != key:
        return False
    right = getattr(clause, "right", None)
    return type(right).__name__ == "Null"


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
