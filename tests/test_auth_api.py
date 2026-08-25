import asyncio
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException
from fastapi.security import HTTPAuthorizationCredentials
from httpx import AsyncClient, Response

from main import create_access_token, get_current_user, hash_password, verify_password
from models import RefreshToken, User
from tests.mock_db import MockSessionFactory


async def create_session_access_token(
    session_factory: MockSessionFactory,
    user: User,
) -> str:
    session_id = await create_session_id(session_factory, user)
    return create_access_token(
        user.id,
        user.email,
        user.email_verified,
        session_id,
    )


async def create_session_id(
    session_factory: MockSessionFactory,
    user: User,
) -> UUID:
    async with session_factory() as session:
        refresh_token = RefreshToken(
            user_id=user.id,
            token_hash="test-token-hash",
            expires_at=datetime.now(UTC) + timedelta(days=30),
        )
        session.add(refresh_token)
        await session.commit()
        return refresh_token.family_id


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


async def test_login_wrong_password_is_rejected(client: AsyncClient) -> None:
    response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "wrong-horse-password"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


async def test_login_short_password_returns_401(client: AsyncClient) -> None:
    response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "short"},
    )

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password"


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


async def test_logout_invalidates_access_token(client: AsyncClient) -> None:
    login_response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    access_token = login_response.json()["access_token"]
    refresh_token = login_response.json()["refresh_token"]

    me_response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_response.status_code == 200

    logout_response = await client.post(
        "/auth/logout",
        json={"refresh_token": refresh_token},
    )
    assert logout_response.status_code == 204

    me_after_logout = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert_invalid_access_token(me_after_logout)


async def test_logout_does_not_invalidate_other_session_access_token(
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
    first_access_token = first_login.json()["access_token"]
    second_access_token = second_login.json()["access_token"]

    logout_response = await client.post(
        "/auth/logout",
        json={"refresh_token": first_login.json()["refresh_token"]},
    )
    assert logout_response.status_code == 204

    first_me = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {first_access_token}"},
    )
    second_me = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {second_access_token}"},
    )
    assert_invalid_access_token(first_me)
    assert second_me.status_code == 200


async def test_refresh_keeps_access_token_valid(client: AsyncClient) -> None:
    login_response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    access_token = login_response.json()["access_token"]
    refresh_token = login_response.json()["refresh_token"]

    refresh_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": refresh_token},
    )
    assert refresh_response.status_code == 200

    me_response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert me_response.status_code == 200


async def test_refresh_reuse_invalidates_session_access_tokens(
    client: AsyncClient,
) -> None:
    login_response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    original_access_token = login_response.json()["access_token"]
    original_refresh_token = login_response.json()["refresh_token"]

    refresh_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": original_refresh_token},
    )
    assert refresh_response.status_code == 200
    rotated_access_token = refresh_response.json()["access_token"]

    reused_response = await client.post(
        "/auth/refresh",
        json={"refresh_token": original_refresh_token},
    )
    assert reused_response.status_code == 401

    original_me = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {original_access_token}"},
    )
    rotated_me = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {rotated_access_token}"},
    )
    assert_invalid_access_token(original_me)
    assert_invalid_access_token(rotated_me)


def assert_invalid_access_token(response: Response) -> None:
    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired access token"
    assert response.headers["www-authenticate"] == "Bearer"


def assert_unauthorized_gate(error: HTTPException) -> None:
    assert error.status_code == 401
    assert error.detail == "Invalid or expired access token"
    assert error.headers == {"WWW-Authenticate": "Bearer"}


async def test_signup_returns_tokens_and_current_user(client: AsyncClient) -> None:
    response = await client.post(
        "/auth/signup",
        json={
            "email": "ada@example.com",
            "password": "correct-horse",
            "display_name": "Ada",
        },
    )
    assert response.status_code == 201
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]
    assert body["refresh_token"]
    assert body["expires_in"] > 0
    assert body["user"]["email"] == "ada@example.com"
    assert body["user"]["display_name"] == "Ada"
    assert body["user"]["email_verified"] is False

    me_response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {body['access_token']}"},
    )
    assert me_response.status_code == 200
    me = me_response.json()
    assert me["id"] == body["user"]["id"]
    assert me["email"] == "ada@example.com"
    assert me["display_name"] == "Ada"


async def test_signup_duplicate_email_returns_409(client: AsyncClient) -> None:
    response = await client.post(
        "/auth/signup",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "Email is already registered"


async def test_signup_rejects_short_password(client: AsyncClient) -> None:
    response = await client.post(
        "/auth/signup",
        json={"email": "ada@example.com", "password": "short"},
    )
    assert response.status_code == 422


async def test_get_me_returns_authenticated_user(client: AsyncClient) -> None:
    login_response = await client.post(
        "/auth/login",
        json={"email": "user@example.com", "password": "correct-horse"},
    )
    assert login_response.status_code == 200
    access_token = login_response.json()["access_token"]

    response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["email"] == "user@example.com"
    assert body["email_verified"] is True


@pytest.mark.parametrize(
    "headers",
    [
        None,
        {},
        {"Authorization": "Bearer"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Token not-a-jwt"},
        {"Authorization": "Bearer not-a-token"},
    ],
    ids=[
        "omitted-headers",
        "missing-authorization",
        "bearer-without-credentials",
        "basic-scheme",
        "token-scheme",
        "malformed-jwt",
    ],
)
async def test_get_me_rejects_invalid_authorization(
    client: AsyncClient,
    headers: dict[str, str] | None,
) -> None:
    response = await client.get("/auth/me", headers=headers)
    assert_invalid_access_token(response)


async def test_get_me_rejects_expired_access_token(
    client: AsyncClient,
    seeded_user: User,
) -> None:
    token = create_access_token(
        seeded_user.id,
        seeded_user.email,
        seeded_user.email_verified,
        uuid4(),
        expires_minutes=-1,
    )
    response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_invalid_access_token(response)


async def test_get_me_rejects_access_token_for_unknown_user(
    client: AsyncClient,
) -> None:
    token = create_access_token(
        uuid4(),
        "ghost@example.com",
        email_verified=False,
        session_id=uuid4(),
    )
    response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_invalid_access_token(response)


async def test_get_me_rejects_access_token_for_unknown_session(
    client: AsyncClient,
    seeded_user: User,
) -> None:
    token = create_access_token(
        seeded_user.id,
        seeded_user.email,
        seeded_user.email_verified,
        uuid4(),
    )
    response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert_invalid_access_token(response)


async def test_patch_me_updates_profile(
    client: AsyncClient,
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    token = await create_session_access_token(session_factory, seeded_user)
    response = await client.patch(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "display_name": "Ada Lovelace",
            "photo_url": "https://cdn.example.com/ada.png",
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == str(seeded_user.id)
    assert body["display_name"] == "Ada Lovelace"
    assert body["photo_url"] == "https://cdn.example.com/ada.png"

    me_response = await client.get(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_response.status_code == 200
    assert me_response.json()["display_name"] == "Ada Lovelace"
    assert me_response.json()["photo_url"] == "https://cdn.example.com/ada.png"


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"display_name": None},
        {"photo_url": None},
        {"display_name": None, "photo_url": None},
    ],
)
async def test_patch_me_rejects_empty_update(
    client: AsyncClient,
    session_factory: MockSessionFactory,
    seeded_user: User,
    payload: dict[str, None],
) -> None:
    token = await create_session_access_token(session_factory, seeded_user)
    response = await client.patch(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
        json=payload,
    )
    assert response.status_code == 422
    assert any(
        error["type"] == "value_error"
        and "at least one of display_name or photo_url is required" in error["msg"]
        for error in response.json()["detail"]
    )


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer"},
        {"Authorization": "Basic dXNlcjpwYXNz"},
        {"Authorization": "Bearer not-a-token"},
    ],
    ids=[
        "missing-authorization",
        "bearer-without-credentials",
        "basic-scheme",
        "malformed-jwt",
    ],
)
async def test_patch_me_rejects_invalid_authorization(
    client: AsyncClient,
    headers: dict[str, str],
) -> None:
    response = await client.patch(
        "/auth/me",
        headers=headers,
        json={"display_name": "Ada"},
    )
    assert_invalid_access_token(response)


async def test_patch_me_rejects_expired_access_token(
    client: AsyncClient,
    seeded_user: User,
) -> None:
    token = create_access_token(
        seeded_user.id,
        seeded_user.email,
        seeded_user.email_verified,
        uuid4(),
        expires_minutes=-1,
    )
    response = await client.patch(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
        json={"display_name": "Ada"},
    )
    assert_invalid_access_token(response)


async def test_patch_me_rejects_access_token_for_unknown_user(
    client: AsyncClient,
) -> None:
    token = create_access_token(
        uuid4(),
        "ghost@example.com",
        email_verified=False,
        session_id=uuid4(),
    )
    response = await client.patch(
        "/auth/me",
        headers={"Authorization": f"Bearer {token}"},
        json={"display_name": "Ada"},
    )
    assert_invalid_access_token(response)


async def test_get_current_user_rejects_missing_credentials(
    session_factory: MockSessionFactory,
) -> None:
    async with session_factory() as session:
        with pytest.raises(HTTPException) as error:
            await get_current_user(None, session)
    assert_unauthorized_gate(error.value)


async def test_get_current_user_rejects_non_bearer_scheme(
    session_factory: MockSessionFactory,
) -> None:
    credentials = HTTPAuthorizationCredentials(scheme="Basic", credentials="abc")
    async with session_factory() as session:
        with pytest.raises(HTTPException) as error:
            await get_current_user(credentials, session)
    assert_unauthorized_gate(error.value)


async def test_get_current_user_rejects_invalid_token(
    session_factory: MockSessionFactory,
) -> None:
    credentials = HTTPAuthorizationCredentials(
        scheme="Bearer",
        credentials="not-a-token",
    )
    async with session_factory() as session:
        with pytest.raises(HTTPException) as error:
            await get_current_user(credentials, session)
    assert_unauthorized_gate(error.value)


async def test_get_current_user_rejects_unknown_user(
    session_factory: MockSessionFactory,
) -> None:
    token = create_access_token(
        uuid4(),
        "ghost@example.com",
        email_verified=False,
        session_id=uuid4(),
    )
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    async with session_factory() as session:
        with pytest.raises(HTTPException) as error:
            await get_current_user(credentials, session)
    assert_unauthorized_gate(error.value)


async def test_get_current_user_rejects_unknown_session(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    token = create_access_token(
        seeded_user.id,
        seeded_user.email,
        seeded_user.email_verified,
        uuid4(),
    )
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    async with session_factory() as session:
        with pytest.raises(HTTPException) as error:
            await get_current_user(credentials, session)
    assert_unauthorized_gate(error.value)


async def test_get_current_user_returns_matching_user(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    token = await create_session_access_token(session_factory, seeded_user)
    credentials = HTTPAuthorizationCredentials(scheme="Bearer", credentials=token)
    async with session_factory() as session:
        user = await get_current_user(credentials, session)
    assert user.id == seeded_user.id
    assert user.email == seeded_user.email
