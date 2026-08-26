import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import HTTPException

from auth.refresh_token import (
    build_refresh_token_value,
    derive_refresh_token_secret,
    get_valid_refresh_token,
    hash_refresh_token_secret,
    is_refresh_token_active,
    issue_refresh_token,
    parse_refresh_token,
    revoke_refresh_token,
    verify_refresh_token_secret,
)
from models import RefreshToken, User
from tests.mock_db import MockSessionFactory


def test_hash_refresh_token_secret_is_deterministic() -> None:
    assert hash_refresh_token_secret("secret") == hash_refresh_token_secret("secret")
    assert hash_refresh_token_secret("secret") != hash_refresh_token_secret("other")


def test_derive_refresh_token_secret_is_keyed_to_id() -> None:
    token_id = uuid4()
    other_id = uuid4()
    secret = derive_refresh_token_secret(token_id)
    assert secret == derive_refresh_token_secret(token_id)
    assert secret != derive_refresh_token_secret(other_id)
    assert not verify_refresh_token_secret(secret, hash_refresh_token_secret("secret"))


def test_parse_refresh_token_round_trip() -> None:
    token_id = uuid4()
    secret = "refresh-secret"

    token = build_refresh_token_value(token_id, secret)
    parsed_id, parsed_secret = parse_refresh_token(token)

    assert parsed_id == token_id
    assert parsed_secret == secret


@pytest.mark.parametrize(
    "token",
    [
        "",
        "not-a-uuid.secret",
        "550e8400-e29b-41d4-a716-446655440000",
        "550e8400-e29b-41d4-a716-446655440000.",
        ".secret",
    ],
)
def test_parse_refresh_token_rejects_invalid_values(token: str) -> None:
    with pytest.raises(ValueError, match="invalid refresh token"):
        parse_refresh_token(token)


def test_verify_refresh_token_secret() -> None:
    secret = "refresh-secret"
    token_hash = hash_refresh_token_secret(secret)

    assert verify_refresh_token_secret(secret, token_hash)
    assert not verify_refresh_token_secret("wrong-secret", token_hash)


def test_is_refresh_token_active() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    active = RefreshToken(
        user_id=uuid4(),
        token_hash="hash",
        expires_at=now + timedelta(days=1),
    )
    revoked = RefreshToken(
        user_id=uuid4(),
        token_hash="hash",
        expires_at=now + timedelta(days=1),
        revoked_at=now,
    )
    expired = RefreshToken(
        user_id=uuid4(),
        token_hash="hash",
        expires_at=now - timedelta(seconds=1),
    )

    assert is_refresh_token_active(active, now)
    assert not is_refresh_token_active(revoked, now)
    assert not is_refresh_token_active(expired, now)


async def test_issue_and_validate_refresh_token(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        _, token = await issue_refresh_token(session, user)
        await session.commit()

    async with session_factory() as session:
        refresh_token, user = await get_valid_refresh_token(session, token)

        assert refresh_token.user_id == user.id
        assert user.email == "user@example.com"


async def test_issue_refresh_token_does_not_persist_secret(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        token_id, token = await issue_refresh_token(session, user)
        await session.commit()
        _, secret = parse_refresh_token(token)
        stored = await session.get(RefreshToken, token_id)
        assert stored is not None
        assert stored.token_hash != secret
        assert stored.token_hash != token
        for value in stored.__dict__.values():
            assert value != token
            assert value != secret


async def test_revoke_refresh_token_claims_only_once(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        _, token = await issue_refresh_token(session, user)
        await session.commit()

    async def claim() -> bool:
        async with session_factory() as session:
            refresh_token, _ = await get_valid_refresh_token(session, token)
            claimed = await revoke_refresh_token(session, refresh_token)
            await session.commit()
            return claimed

    results = await asyncio.gather(claim(), claim(), return_exceptions=True)
    successes = [result for result in results if result is True]
    failures = [
        result
        for result in results
        if result is False
        or (isinstance(result, HTTPException) and result.status_code == 401)
    ]
    assert len(successes) == 1
    assert len(failures) == 1


async def test_expired_refresh_token_is_rejected(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        secret = "refresh-secret"
        refresh_token = RefreshToken(
            user_id=user.id,
            token_hash=hash_refresh_token_secret(secret),
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        session.add(refresh_token)
        await session.commit()
        token = build_refresh_token_value(refresh_token.id, secret)

    async with session_factory() as session:
        with pytest.raises(HTTPException) as error:
            await get_valid_refresh_token(session, token)
        assert error.value.status_code == 401
