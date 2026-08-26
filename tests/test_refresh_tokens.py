import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import HTTPException

from main import (
    build_refresh_token_value,
    derive_refresh_token_secret,
    get_valid_refresh_token,
    hash_refresh_token_secret,
    is_refresh_token_active,
    is_within_reuse_grace,
    issue_refresh_token,
    parse_refresh_token,
    reject_refresh_token_reuse,
    revoke_refresh_token,
    verify_refresh_token_secret,
)
from models import RefreshToken, User
from refresh_token_purge import purge_expired_refresh_tokens
from settings import settings
from tests.mock_db import MockSessionFactory, MockStore


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


def test_is_within_reuse_grace() -> None:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    grace = timedelta(seconds=settings.jwt_refresh_reuse_grace_seconds)

    assert is_within_reuse_grace(now, now)
    assert is_within_reuse_grace(now - grace, now)
    assert not is_within_reuse_grace(now - grace - timedelta(seconds=1), now)


async def test_issue_and_validate_refresh_token(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        token = await issue_refresh_token(session, user)
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
        token = await issue_refresh_token(session, user)
        await session.commit()
        token_id, secret = parse_refresh_token(token)
        stored = await session.get(RefreshToken, token_id)
        assert stored is not None
        assert stored.token_hash != secret
        assert stored.token_hash != token
        assert stored.replaced_by_id is None
        for value in stored.__dict__.values():
            assert value != token
            assert value != secret


async def test_refresh_token_reuse_revokes_family(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        original = await issue_refresh_token(session, user)
        other_session = await issue_refresh_token(session, user)
        await session.commit()
        refresh_token, _ = await get_valid_refresh_token(session, original)
        assert await revoke_refresh_token(session, refresh_token)
        rotated = await issue_refresh_token(
            session,
            user,
            family_id=refresh_token.family_id,
        )
        rotated_id, _ = parse_refresh_token(rotated)
        refresh_token.replaced_by_id = rotated_id
        refresh_token.revoked_at = datetime.now(UTC) - timedelta(
            seconds=settings.jwt_refresh_reuse_grace_seconds + 1
        )
        await session.commit()

    async with session_factory() as session:
        stored = await session.get(RefreshToken, refresh_token.id)
        assert stored is not None
        user = await session.get(User, seeded_user.id)
        assert user is not None
        with pytest.raises(HTTPException) as error:
            await reject_refresh_token_reuse(session, stored, user)
        assert error.value.status_code == 401

        with pytest.raises(HTTPException) as rotated_error:
            await get_valid_refresh_token(session, rotated)
        assert rotated_error.value.status_code == 401

        surviving, _ = await get_valid_refresh_token(session, other_session)
        assert is_refresh_token_active(surviving)


async def test_refresh_token_reuse_within_grace_returns_current_pair(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        original = await issue_refresh_token(session, user)
        await session.commit()
        refresh_token, _ = await get_valid_refresh_token(session, original)
        rotated = await issue_refresh_token(
            session,
            user,
            family_id=refresh_token.family_id,
        )
        assert await revoke_refresh_token(
            session,
            refresh_token,
            replaced_by_id=parse_refresh_token(rotated)[0],
        )
        await session.commit()

    async with session_factory() as session:
        stored = await session.get(RefreshToken, refresh_token.id)
        assert stored is not None
        user = await session.get(User, seeded_user.id)
        assert user is not None
        assert stored.replaced_by_id == parse_refresh_token(rotated)[0]
        assert rotated not in stored.__dict__.values()
        _, rotated_secret = parse_refresh_token(rotated)
        assert rotated_secret not in stored.__dict__.values()
        replayed = await reject_refresh_token_reuse(session, stored, user)
        assert replayed.refresh_token == rotated
        surviving, _ = await get_valid_refresh_token(session, rotated)
        assert is_refresh_token_active(surviving)


async def test_invalid_refresh_secret_does_not_revoke_family(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        original = await issue_refresh_token(session, user)
        await session.commit()
        refresh_token, _ = await get_valid_refresh_token(session, original)
        assert await revoke_refresh_token(session, refresh_token)
        rotated = await issue_refresh_token(
            session,
            user,
            family_id=refresh_token.family_id,
        )
        await session.commit()
        token_id, _ = parse_refresh_token(original)
        forged = build_refresh_token_value(token_id, "wrong-secret")

    async with session_factory() as session:
        with pytest.raises(HTTPException) as error:
            await get_valid_refresh_token(session, forged)
        assert error.value.status_code == 401

        surviving, _ = await get_valid_refresh_token(session, rotated)
        assert is_refresh_token_active(surviving)


async def test_expired_refresh_token_does_not_revoke_family(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    family_id = uuid4()
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        secret = "refresh-secret"
        expired = RefreshToken(
            user_id=user.id,
            family_id=family_id,
            token_hash=hash_refresh_token_secret(secret),
            expires_at=datetime.now(UTC) - timedelta(seconds=1),
        )
        session.add(expired)
        await session.flush()
        expired_token = build_refresh_token_value(expired.id, secret)
        sibling = await issue_refresh_token(session, user, family_id=family_id)
        await session.commit()

    async with session_factory() as session:
        with pytest.raises(HTTPException) as error:
            await get_valid_refresh_token(session, expired_token)
        assert error.value.status_code == 401

        surviving, _ = await get_valid_refresh_token(session, sibling)
        assert is_refresh_token_active(surviving)


async def test_revoke_refresh_token_claims_only_once(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        token = await issue_refresh_token(session, user)
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


async def test_purge_expired_refresh_tokens_deletes_expired_only(
    session_factory: MockSessionFactory,
    mock_store: MockStore,
    seeded_user: User,
) -> None:
    now = datetime.now(UTC)
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        expired = RefreshToken(
            user_id=user.id,
            token_hash=hash_refresh_token_secret("expired"),
            expires_at=now - timedelta(seconds=1),
        )
        expired_revoked = RefreshToken(
            user_id=user.id,
            token_hash=hash_refresh_token_secret("expired-revoked"),
            expires_at=now - timedelta(seconds=1),
            revoked_at=now - timedelta(hours=1),
        )
        active = RefreshToken(
            user_id=user.id,
            token_hash=hash_refresh_token_secret("active"),
            expires_at=now + timedelta(days=1),
        )
        revoked_unexpired = RefreshToken(
            user_id=user.id,
            token_hash=hash_refresh_token_secret("revoked"),
            expires_at=now + timedelta(days=1),
            revoked_at=now,
        )
        session.add(expired)
        session.add(expired_revoked)
        session.add(active)
        session.add(revoked_unexpired)
        await session.commit()
        active_id = active.id
        revoked_unexpired_id = revoked_unexpired.id
        expired_id = expired.id
        expired_revoked_id = expired_revoked.id

    async with session_factory() as session:
        deleted = await purge_expired_refresh_tokens(session, now=now, limit=1000)
        await session.commit()

    assert deleted == 2
    assert expired_id not in mock_store.refresh_tokens
    assert expired_revoked_id not in mock_store.refresh_tokens
    assert active_id in mock_store.refresh_tokens
    assert revoked_unexpired_id in mock_store.refresh_tokens


async def test_purge_expired_refresh_tokens_batches(
    session_factory: MockSessionFactory,
    mock_store: MockStore,
    seeded_user: User,
) -> None:
    now = datetime.now(UTC)
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        for index in range(5):
            session.add(
                RefreshToken(
                    user_id=user.id,
                    token_hash=hash_refresh_token_secret(f"expired-{index}"),
                    expires_at=now - timedelta(seconds=1),
                )
            )
        session.add(
            RefreshToken(
                user_id=user.id,
                token_hash=hash_refresh_token_secret("active"),
                expires_at=now + timedelta(days=1),
            )
        )
        await session.commit()

    async with session_factory() as session:
        deleted = await purge_expired_refresh_tokens(session, now=now, limit=2)
        await session.commit()

    assert deleted == 5
    assert len(mock_store.refresh_tokens) == 1
    remaining = next(iter(mock_store.refresh_tokens.values()))
    assert remaining.expires_at > now


async def test_purge_keeps_revoked_unexpired_for_reuse_detection(
    session_factory: MockSessionFactory,
    seeded_user: User,
) -> None:
    async with session_factory() as session:
        user = await session.get(User, seeded_user.id)
        assert user is not None
        original = await issue_refresh_token(session, user)
        await session.commit()
        refresh_token, _ = await get_valid_refresh_token(session, original)
        assert await revoke_refresh_token(session, refresh_token)
        rotated = await issue_refresh_token(
            session,
            user,
            family_id=refresh_token.family_id,
        )
        rotated_id, _ = parse_refresh_token(rotated)
        refresh_token.replaced_by_id = rotated_id
        refresh_token.revoked_at = datetime.now(UTC) - timedelta(
            seconds=settings.jwt_refresh_reuse_grace_seconds + 1
        )
        await session.commit()

    async with session_factory() as session:
        deleted = await purge_expired_refresh_tokens(session, limit=1000)
        await session.commit()
        assert deleted == 0

    async with session_factory() as session:
        stored = await session.get(RefreshToken, refresh_token.id)
        assert stored is not None
        user = await session.get(User, seeded_user.id)
        assert user is not None
        with pytest.raises(HTTPException) as error:
            await reject_refresh_token_reuse(session, stored, user)
        assert error.value.status_code == 401

        with pytest.raises(HTTPException) as rotated_error:
            await get_valid_refresh_token(session, rotated)
        assert rotated_error.value.status_code == 401
