import asyncio
from collections.abc import Awaitable, Callable
from uuid import UUID

from httpx import AsyncClient

from app.db.models import ServiceClient, User
from app.service.opaque_token import OpaqueToken


def _reset_token_id(reset_token: str) -> UUID:
    token_id, _ = OpaqueToken.parse(reset_token)
    return token_id


async def test_password_reset_request_happy_path_returns_token(
    client: AsyncClient,
    seeded_service_client: tuple[ServiceClient, str],
) -> None:
    _, key = seeded_service_client

    response = await client.post(
        "/auth/password-reset/request",
        json={"email": "user@example.com"},
        headers={"X-Service-Key": key},
    )

    assert response.status_code == 200
    reset_token = response.json()["reset_token"]
    assert reset_token is not None
    token_id, secret = reset_token.split(".", 1)
    assert UUID(token_id)
    assert secret


async def test_password_reset_request_unknown_email_returns_no_token(
    client: AsyncClient,
    seeded_service_client: tuple[ServiceClient, str],
) -> None:
    _, key = seeded_service_client

    response = await client.post(
        "/auth/password-reset/request",
        json={"email": "missing@example.com"},
        headers={"X-Service-Key": key},
    )

    assert response.status_code == 200
    assert response.json()["reset_token"] is None


async def test_password_reset_request_missing_service_key_is_rejected(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/auth/password-reset/request",
        json={"email": "user@example.com"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or revoked service key"


async def test_password_reset_request_wrong_service_key_is_rejected(
    client: AsyncClient,
    seeded_service_client: tuple[ServiceClient, str],
) -> None:
    response = await client.post(
        "/auth/password-reset/request",
        json={"email": "user@example.com"},
        headers={"X-Service-Key": "not-a-real-key"},
    )

    assert response.status_code == 401


async def test_password_reset_request_revoked_service_key_is_rejected(
    client: AsyncClient,
    revoked_service_client: tuple[ServiceClient, str],
) -> None:
    _, key = revoked_service_client

    response = await client.post(
        "/auth/password-reset/request",
        json={"email": "user@example.com"},
        headers={"X-Service-Key": key},
    )

    assert response.status_code == 401


async def _request_reset_token(client: AsyncClient, key: str, email: str = "user@example.com") -> str:
    response = await client.post(
        "/auth/password-reset/request",
        json={"email": email},
        headers={"X-Service-Key": key},
    )
    reset_token = response.json()["reset_token"]
    assert reset_token is not None
    return reset_token


async def test_password_reset_confirm_happy_path(
    client: AsyncClient,
    seeded_service_client: tuple[ServiceClient, str],
) -> None:
    _, key = seeded_service_client
    reset_token = await _request_reset_token(client, key)

    confirm = await client.post(
        "/auth/password-reset/confirm",
        json={"token": reset_token, "new_password": "new-correct-horse"},
    )
    assert confirm.status_code == 204

    new_login = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "new-correct-horse"},
    )
    assert new_login.status_code == 200

    old_login = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    assert old_login.status_code == 401


async def test_password_reset_confirm_sets_email_verified_true(
    client: AsyncClient,
    seeded_service_client: tuple[ServiceClient, str],
    unverified_user: User,
) -> None:
    _, key = seeded_service_client
    reset_token = await _request_reset_token(client, key, email=unverified_user.email)

    confirm = await client.post(
        "/auth/password-reset/confirm",
        json={"token": reset_token, "new_password": "new-correct-horse"},
    )
    assert confirm.status_code == 204

    login = await client.post(
        "/auth/login",
        json={"email": unverified_user.email, "password": "new-correct-horse"},
    )
    assert login.status_code == 200

    me = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {login.json()['access_token']}"},
    )
    assert me.status_code == 200
    assert me.json()["email_verified"] is True


async def test_password_reset_confirm_revokes_all_sessions_across_families(
    client: AsyncClient,
    seeded_service_client: tuple[ServiceClient, str],
) -> None:
    _, key = seeded_service_client

    first_login = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    second_login = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    first_rt = first_login.json()["refresh_token"]
    second_rt = second_login.json()["refresh_token"]

    reset_token = await _request_reset_token(client, key)
    confirm = await client.post(
        "/auth/password-reset/confirm",
        json={"token": reset_token, "new_password": "new-correct-horse"},
    )
    assert confirm.status_code == 204

    first_refresh = await client.post("/auth/refresh", json={"refresh_token": first_rt})
    second_refresh = await client.post("/auth/refresh", json={"refresh_token": second_rt})
    assert first_refresh.status_code == 401
    assert second_refresh.status_code == 401


async def test_password_reset_confirm_expired_token_rejected(
    client: AsyncClient,
    seeded_service_client: tuple[ServiceClient, str],
    expire_password_reset_token: Callable[[UUID], Awaitable[None]],
) -> None:
    _, key = seeded_service_client
    reset_token = await _request_reset_token(client, key)
    await expire_password_reset_token(_reset_token_id(reset_token))

    confirm = await client.post(
        "/auth/password-reset/confirm",
        json={"token": reset_token, "new_password": "new-correct-horse"},
    )
    assert confirm.status_code == 400
    assert confirm.json()["detail"] == "Invalid or expired reset token"


async def test_password_reset_confirm_already_used_token_rejected(
    client: AsyncClient,
    seeded_service_client: tuple[ServiceClient, str],
) -> None:
    _, key = seeded_service_client
    reset_token = await _request_reset_token(client, key)

    first = await client.post(
        "/auth/password-reset/confirm",
        json={"token": reset_token, "new_password": "new-correct-horse"},
    )
    assert first.status_code == 204

    second = await client.post(
        "/auth/password-reset/confirm",
        json={"token": reset_token, "new_password": "another-correct-horse"},
    )
    assert second.status_code == 400


async def test_password_reset_confirm_malformed_token_rejected(
    client: AsyncClient,
) -> None:
    response = await client.post(
        "/auth/password-reset/confirm",
        json={"token": "not-a-valid-token", "new_password": "new-correct-horse"},
    )
    assert response.status_code == 400


async def test_password_reset_confirm_wrong_secret_rejected(
    client: AsyncClient,
    seeded_service_client: tuple[ServiceClient, str],
) -> None:
    _, key = seeded_service_client
    reset_token = await _request_reset_token(client, key)
    token_id = _reset_token_id(reset_token)

    response = await client.post(
        "/auth/password-reset/confirm",
        json={"token": f"{token_id}.wrong-secret", "new_password": "new-correct-horse"},
    )
    assert response.status_code == 400


async def test_password_reset_confirm_weak_new_password_rejected(
    client: AsyncClient,
    seeded_service_client: tuple[ServiceClient, str],
) -> None:
    _, key = seeded_service_client
    reset_token = await _request_reset_token(client, key)

    response = await client.post(
        "/auth/password-reset/confirm",
        json={"token": reset_token, "new_password": "short"},
    )
    assert response.status_code == 422


async def test_password_reset_concurrent_confirm_only_one_succeeds(
    client: AsyncClient,
    seeded_service_client: tuple[ServiceClient, str],
) -> None:
    _, key = seeded_service_client
    reset_token = await _request_reset_token(client, key)

    first, second = await asyncio.gather(
        client.post(
            "/auth/password-reset/confirm",
            json={"token": reset_token, "new_password": "new-correct-horse"},
        ),
        client.post(
            "/auth/password-reset/confirm",
            json={"token": reset_token, "new_password": "another-correct-horse"},
        ),
    )

    statuses = sorted([first.status_code, second.status_code])
    assert statuses == [204, 400]
