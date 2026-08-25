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
        if isinstance(statement, Select):
            return _execute_select(self._store, statement)
        if type(statement).__name__ == "Delete":
            return _execute_delete(self._store, statement)
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
    def __init__(
        self,
        value: UUID | None = None,
        values: list[UUID] | None = None,
    ) -> None:
        self._value = value
        self._values = values or ([] if value is None else [value])

    def scalar_one_or_none(self) -> UUID | None:
        return self._value

    def scalars(self) -> MockResult:
        return self

    def all(self) -> list[UUID]:
        return list(self._values)


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


def _execute_select(store: MockStore, statement: Select[Any]) -> MockResult:
    descriptions = statement.column_descriptions
    if not descriptions:
        return MockResult(values=[])
    expr = descriptions[0].get("expr")
    if getattr(expr, "key", None) != "id":
        token = _find_refresh_token(store, statement)
        return MockResult(values=[] if token is None else [token.id])
    expires_at_max = _expires_at_filter(statement.whereclause)
    matched: list[UUID] = []
    for token in store.refresh_tokens.values():
        if expires_at_max is not None and not _expires_at_lte(token, expires_at_max):
            continue
        matched.append(token.id)
    limit = _select_limit(statement)
    if limit is not None:
        matched = matched[:limit]
    return MockResult(values=matched)


def _execute_delete(store: MockStore, statement: Any) -> MockResult:
    where = getattr(statement, "whereclause", None)
    if where is None:
        return MockResult(values=[])
    token_ids: set[UUID] | None = None
    user_id: UUID | None = None
    family_id: UUID | None = None
    expires_at_max: datetime | None = None
    for clause in _iter_where_clauses(where):
        if token_ids is None:
            token_ids = _uuids_from_in_clause(clause, "id")
        if user_id is None:
            user_id = _uuid_from_clause(clause, "user_id")
        if family_id is None:
            family_id = _uuid_from_clause(clause, "family_id")
        if expires_at_max is None:
            expires_at_max = _datetime_le_from_clause(clause, "expires_at")
    deleted: list[UUID] = []
    for token_id, token in list(store.refresh_tokens.items()):
        if token_ids is not None and token_id not in token_ids:
            continue
        if user_id is not None and token.user_id != user_id:
            continue
        if family_id is not None and token.family_id != family_id:
            continue
        if expires_at_max is not None and not _expires_at_lte(token, expires_at_max):
            continue
        del store.refresh_tokens[token_id]
        deleted.append(token_id)
    return MockResult(values=deleted)


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


def _expires_at_lte(token: RefreshToken, cutoff: datetime) -> bool:
    expires_at = token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    compare = cutoff
    if compare.tzinfo is None:
        compare = compare.replace(tzinfo=UTC)
    return expires_at <= compare


def _expires_at_filter(where: Any) -> datetime | None:
    if where is None:
        return None
    for clause in _iter_where_clauses(where):
        if value := _datetime_le_from_clause(clause, "expires_at"):
            return value
    return None


def _select_limit(statement: Select[Any]) -> int | None:
    limit_clause = getattr(statement, "_limit_clause", None)
    if limit_clause is None:
        return None
    value = getattr(limit_clause, "value", limit_clause)
    return value if isinstance(value, int) else None


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


def _uuids_from_in_clause(clause: Any, key: str) -> set[UUID] | None:
    left = getattr(clause, "left", None)
    if getattr(left, "key", None) != key:
        return None
    right = getattr(clause, "right", None)
    value = getattr(right, "value", None)
    if isinstance(value, (list, tuple, set)):
        return {item for item in value if isinstance(item, UUID)}
    if type(right).__name__ == "ClauseList":
        found: set[UUID] = set()
        for child in getattr(right, "get_children", lambda: ())():
            child_value = getattr(child, "value", child)
            if isinstance(child_value, UUID):
                found.add(child_value)
        return found
    return None


def _datetime_le_from_clause(clause: Any, key: str) -> datetime | None:
    left = getattr(clause, "left", None)
    if getattr(left, "key", None) != key:
        return None
    operator = getattr(clause, "operator", None)
    op_name = getattr(operator, "__name__", str(operator))
    if op_name not in {"le", "lt", "<="}:
        return None
    right = getattr(clause, "right", None)
    value = getattr(right, "value", None)
    return value if isinstance(value, datetime) else None


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
