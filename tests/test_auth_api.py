import asyncio

import pytest
from httpx import AsyncClient

from main import hash_password, verify_password


@pytest.mark.asyncio
async def test_login_unknown_email_hashes_random_dummy(
    client: AsyncClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hashed_secrets: list[str] = []
    verified: list[tuple[str, str]] = []
    original_hash = hash_password
    original_verify = verify_password

    def tracked_hash(password: str) -> str:
        hashed_secrets.append(password)
        return original_hash(password)

    def tracked_verify(password: str, password_hash: str) -> bool:
        verified.append((password, password_hash))
        return original_verify(password, password_hash)

    monkeypatch.setattr("main.hash_password", tracked_hash)
    monkeypatch.setattr("main.verify_password", tracked_verify)

    response = await client.post(
        "/auth/login",
        json={"email": "missing@example.com", "password": "correct-horse"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"
    assert len(hashed_secrets) == 1
    assert hashed_secrets[0] != "correct-horse"
    assert verified == []


@pytest.mark.asyncio
async def test_login_wrong_password_is_rejected(client: AsyncClient) -> None:
    response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "wrong-horse-password"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


@pytest.mark.asyncio
async def test_refresh_endpoint_rotates_token(client: AsyncClient) -> None:
    login_response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    assert login_response.status_code == 200
    original_refresh_token = login_response.json()["refresh_token"]

    refresh_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": original_refresh_token},
    )
    assert refresh_response.status_code == 200
    new_refresh_token = refresh_response.json()["refresh_token"]
    assert new_refresh_token != original_refresh_token

    reused_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": original_refresh_token},
    )
    assert reused_response.status_code == 401

    stolen_successor_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": new_refresh_token},
    )
    assert stolen_successor_response.status_code == 401


@pytest.mark.asyncio
async def test_refresh_reuse_does_not_revoke_other_sessions(
    client: AsyncClient,
) -> None:
    first_login = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    second_login = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    assert first_login.status_code == 200
    assert second_login.status_code == 200
    first_refresh_token = first_login.json()["refresh_token"]
    second_refresh_token = second_login.json()["refresh_token"]

    rotated_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": first_refresh_token},
    )
    assert rotated_response.status_code == 200

    reused_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": first_refresh_token},
    )
    assert reused_response.status_code == 401

    other_session_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": second_refresh_token},
    )
    assert other_session_response.status_code == 200


@pytest.mark.asyncio
async def test_concurrent_refresh_issues_one_token_pair(client: AsyncClient) -> None:
    login_response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    assert login_response.status_code == 200
    original_refresh_token = login_response.json()["refresh_token"]

    first_response, second_response = await asyncio.gather(
        client.post("/auth/refresh", json={"refresh_token": original_refresh_token}),
        client.post("/auth/refresh", json={"refresh_token": original_refresh_token}),
    )
    statuses = sorted([first_response.status_code, second_response.status_code])
    assert statuses == [200, 401]

    winner = first_response if first_response.status_code == 200 else second_response
    rotated_refresh_token = winner.json()["refresh_token"]
    assert rotated_refresh_token != original_refresh_token

    reused_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": original_refresh_token},
    )
    assert reused_response.status_code == 401

    follow_up_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": rotated_refresh_token},
    )
    assert follow_up_response.status_code == 401


@pytest.mark.asyncio
async def test_logout_revokes_refresh_token(client: AsyncClient) -> None:
    login_response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    refresh_token = login_response.json()["refresh_token"]

    logout_response = await client.post(
        "/auth/logout",
        json={"refresh_token": refresh_token},
    )
    assert logout_response.status_code == 204

    refresh_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_response.status_code == 401
