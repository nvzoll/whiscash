import asyncio

import pytest
from httpx import AsyncClient


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
    assert follow_up_response.status_code == 200


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
