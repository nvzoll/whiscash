from collections.abc import Callable
from typing import Any, Self

import pytest
from fastapi import FastAPI, HTTPException, status
from httpx import ASGITransport, AsyncClient
from sqlalchemy.exc import PendingRollbackError

import app.db.session as session_module
from app.db.session import SessionDependency


class FakeSession:
    def __init__(self, commit_error: Exception | None = None) -> None:
        self._commit_error = commit_error
        self.commits = 0
        self.rollbacks = 0

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> bool:
        return False

    async def commit(self) -> None:
        if self._commit_error is not None:
            raise self._commit_error
        self.commits += 1

    async def rollback(self) -> None:
        self.rollbacks += 1


async def ok_endpoint(session: SessionDependency) -> dict[str, bool]:
    return {"ok": True}


async def http_error_endpoint(session: SessionDependency) -> dict[str, bool]:
    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)


async def crash_endpoint(session: SessionDependency) -> dict[str, bool]:
    raise RuntimeError("boom")


def make_client(
    monkeypatch: pytest.MonkeyPatch,
    session: FakeSession,
    endpoint: Callable[..., Any],
) -> AsyncClient:
    monkeypatch.setattr(session_module, "AsyncSessionLocal", lambda: session)
    api = FastAPI()
    api.get("/probe")(endpoint)
    return AsyncClient(
        transport=ASGITransport(app=api, raise_app_exceptions=False),
        base_url="http://test",
    )


async def test_successful_request_commits(monkeypatch: pytest.MonkeyPatch) -> None:
    session = FakeSession()
    async with make_client(monkeypatch, session, ok_endpoint) as client:
        response = await client.get("/probe")

    assert response.status_code == 200
    assert session.commits == 1


async def test_failed_commit_is_not_reported_as_success(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession(commit_error=RuntimeError("commit failed"))
    async with make_client(monkeypatch, session, ok_endpoint) as client:
        response = await client.get("/probe")

    assert response.status_code == 500
    assert session.commits == 0


async def test_http_exception_commits_so_family_revocation_survives(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession()
    async with make_client(monkeypatch, session, http_error_endpoint) as client:
        response = await client.get("/probe")

    assert response.status_code == 401
    assert session.commits == 1
    assert session.rollbacks == 0


async def test_http_exception_with_pending_rollback_keeps_original_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession(commit_error=PendingRollbackError("flush failed"))
    async with make_client(monkeypatch, session, http_error_endpoint) as client:
        response = await client.get("/probe")

    assert response.status_code == 401
    assert session.rollbacks == 1


async def test_unhandled_exception_rolls_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession()
    async with make_client(monkeypatch, session, crash_endpoint) as client:
        response = await client.get("/probe")

    assert response.status_code == 500
    assert session.commits == 0
    assert session.rollbacks == 1
