import asyncio
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.core.config import settings
from app.db.models import RefreshToken, User
from app.service.exceptions import InvalidRefreshTokenError
from app.service.refresh_token import RefreshTokenService
from app.service.service import AuthService
from tests.mocks import MockRefreshTokenRepo, MockStore, MockUserRepo


def expire_refresh_reuse_grace(mock_store: MockStore) -> None:
    past = datetime.now(UTC) - timedelta(seconds=settings.jwt_refresh_reuse_grace_seconds + 1)
    for token in mock_store.refresh_tokens.values():
        if token.revoked_at is not None:
            token.revoked_at = past


def test_hash_secret_is_deterministic() -> None:
    assert RefreshTokenService.hash_secret("secret") == RefreshTokenService.hash_secret("secret")
    assert RefreshTokenService.hash_secret("secret") != RefreshTokenService.hash_secret("other")


def test_generate_secret_is_random() -> None:
    secrets_generated = {RefreshTokenService.generate_secret() for _ in range(10)}
    assert len(secrets_generated) == 10


def test_parse_round_trip() -> None:
    token_id = uuid4()
    secret = "refresh-secret"

    token = RefreshTokenService.build(token_id, secret)
    parsed_id, parsed_secret = RefreshTokenService.parse(token)

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
def test_parse_rejects_invalid_values(token: str) -> None:
    with pytest.raises(ValueError, match="invalid refresh token"):
        RefreshTokenService.parse(token)


def test_verify_secret() -> None:
    secret = "refresh-secret"
    token_hash = RefreshTokenService.hash_secret(secret)

    assert RefreshTokenService.verify_secret(secret, token_hash)
    assert not RefreshTokenService.verify_secret("wrong-secret", token_hash)


def test_is_active() -> None:
    now = datetime.now(UTC)
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

    assert RefreshTokenService.is_active(active)
    assert not RefreshTokenService.is_active(revoked)
    assert not RefreshTokenService.is_active(expired)


async def test_issue_and_validate_refresh_token(
    mock_store: MockStore,
    seeded_user: User,
) -> None:
    service = AuthService(MockUserRepo(mock_store), MockRefreshTokenRepo(mock_store))
    tokens = await service.login("user@example.com", "correct-horse")

    refresh_token = await service._load_refresh_token(tokens.refresh_token, for_update=False)
    user = await service._users.get_by_id(refresh_token.user_id)
    assert user is not None
    assert refresh_token.user_id == user.id
    assert user.email == "user@example.com"


async def test_issue_refresh_token_does_not_persist_secret(
    mock_store: MockStore,
    seeded_user: User,
) -> None:
    service = AuthService(MockUserRepo(mock_store), MockRefreshTokenRepo(mock_store))
    tokens = await service.login("user@example.com", "correct-horse")
    token_id, secret = RefreshTokenService.parse(tokens.refresh_token)
    stored = mock_store.refresh_tokens[token_id]
    assert stored.token_hash != secret
    assert stored.token_hash != tokens.refresh_token
    for value in stored.__dict__.values():
        assert value != tokens.refresh_token
        assert value != secret


async def test_revoke_refresh_token_claims_only_once(
    mock_store: MockStore,
    seeded_user: User,
) -> None:
    refresh_tokens = MockRefreshTokenRepo(mock_store)
    service = AuthService(MockUserRepo(mock_store), refresh_tokens)
    tokens = await service.login("user@example.com", "correct-horse")

    async def claim() -> bool:
        try:
            refresh_token = await service._load_refresh_token(
                tokens.refresh_token,
                for_update=True,
            )
        except InvalidRefreshTokenError:
            return False
        return await refresh_tokens.revoke(refresh_token)

    results = await asyncio.gather(claim(), claim(), return_exceptions=True)
    successes = [result for result in results if result is True]
    failures = [result for result in results if result is False]
    assert len(successes) == 1
    assert len(failures) == 1


async def test_expired_refresh_token_is_rejected(
    mock_store: MockStore,
    seeded_user: User,
) -> None:
    secret = "refresh-secret"
    refresh_token = RefreshToken(
        user_id=seeded_user.id,
        family_id=uuid4(),
        token_hash=RefreshTokenService.hash_secret(secret),
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    mock_store.refresh_tokens[refresh_token.id] = refresh_token
    token = RefreshTokenService.build(refresh_token.id, secret)

    service = AuthService(MockUserRepo(mock_store), MockRefreshTokenRepo(mock_store))
    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(token)


async def test_rotation_keeps_family_id(
    mock_store: MockStore,
    seeded_user: User,
) -> None:
    service = AuthService(MockUserRepo(mock_store), MockRefreshTokenRepo(mock_store))
    tokens = await service.login("user@example.com", "correct-horse")
    original_id, _ = RefreshTokenService.parse(tokens.refresh_token)
    original_family_id = mock_store.refresh_tokens[original_id].family_id

    rotated = await service.refresh(tokens.refresh_token)
    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)

    assert mock_store.refresh_tokens[rotated_id].family_id == original_family_id


async def test_login_mints_new_family_id(
    mock_store: MockStore,
    seeded_user: User,
) -> None:
    service = AuthService(MockUserRepo(mock_store), MockRefreshTokenRepo(mock_store))
    first = await service.login("user@example.com", "correct-horse")
    second = await service.login("user@example.com", "correct-horse")
    first_id, _ = RefreshTokenService.parse(first.refresh_token)
    second_id, _ = RefreshTokenService.parse(second.refresh_token)

    assert mock_store.refresh_tokens[first_id].family_id != mock_store.refresh_tokens[second_id].family_id


async def test_refresh_token_reuse_revokes_family(
    mock_store: MockStore,
    seeded_user: User,
) -> None:
    service = AuthService(MockUserRepo(mock_store), MockRefreshTokenRepo(mock_store))
    tokens = await service.login("user@example.com", "correct-horse")
    original_id, _ = RefreshTokenService.parse(tokens.refresh_token)

    rotated = await service.refresh(tokens.refresh_token)
    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)

    expire_refresh_reuse_grace(mock_store)

    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(tokens.refresh_token)

    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(rotated.refresh_token)

    assert mock_store.refresh_tokens[original_id].revoked_at is not None
    assert mock_store.refresh_tokens[rotated_id].revoked_at is not None


async def test_invalid_refresh_secret_does_not_revoke_family(
    mock_store: MockStore,
    seeded_user: User,
) -> None:
    service = AuthService(MockUserRepo(mock_store), MockRefreshTokenRepo(mock_store))
    tokens = await service.login("user@example.com", "correct-horse")
    rotated = await service.refresh(tokens.refresh_token)
    token_id, _ = RefreshTokenService.parse(tokens.refresh_token)
    forged = RefreshTokenService.build(token_id, "wrong-secret")

    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(forged)

    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)
    assert mock_store.refresh_tokens[rotated_id].revoked_at is None


async def test_expired_refresh_token_does_not_revoke_family(
    mock_store: MockStore,
    seeded_user: User,
) -> None:
    family_id = uuid4()
    secret = "refresh-secret"
    expired = RefreshToken(
        user_id=seeded_user.id,
        family_id=family_id,
        token_hash=RefreshTokenService.hash_secret(secret),
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    mock_store.refresh_tokens[expired.id] = expired
    expired_token = RefreshTokenService.build(expired.id, secret)

    sibling_id = uuid4()
    sibling_secret = RefreshTokenService.generate_secret()
    sibling = RefreshToken(
        id=sibling_id,
        user_id=seeded_user.id,
        family_id=family_id,
        token_hash=RefreshTokenService.hash_secret(sibling_secret),
        expires_at=datetime.now(UTC) + timedelta(days=30),
    )
    mock_store.refresh_tokens[sibling_id] = sibling

    service = AuthService(MockUserRepo(mock_store), MockRefreshTokenRepo(mock_store))
    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(expired_token)

    assert mock_store.refresh_tokens[sibling_id].revoked_at is None
