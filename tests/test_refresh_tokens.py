import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from app.db.models import RefreshToken, User
from app.repository.protocols import PasswordResetTokenRepo, RefreshTokenRepo, ServiceClientRepo, UserRepo
from app.service.exceptions import InvalidRefreshTokenError
from app.service.refresh_token import RefreshTokenService
from app.service.service import AuthService


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
    with pytest.raises(ValueError, match="invalid opaque token"):
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
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    seeded_user: User,
) -> None:
    service = AuthService(user_repo, refresh_token_repo, password_reset_token_repo, service_client_repo)
    tokens = await service.login("user@example.com", "correct-horse")

    refresh_token = await service._load_refresh_token(tokens.refresh_token, for_update=False)
    user = await service._users.get_by_id(refresh_token.user_id)
    assert user is not None
    assert refresh_token.user_id == user.id
    assert user.email == "user@example.com"


async def test_issue_refresh_token_does_not_persist_secret(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    seeded_user: User,
) -> None:
    service = AuthService(user_repo, refresh_token_repo, password_reset_token_repo, service_client_repo)
    tokens = await service.login("user@example.com", "correct-horse")
    token_id, secret = RefreshTokenService.parse(tokens.refresh_token)
    stored = await refresh_token_repo.get_by_id(token_id)
    assert stored is not None
    assert stored.token_hash != secret
    assert stored.token_hash != tokens.refresh_token
    for column in RefreshToken.__table__.columns:
        value = getattr(stored, column.name)
        assert value != tokens.refresh_token
        assert value != secret


async def test_revoke_refresh_token_claims_only_once(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    make_refresh_token_repo: Callable[[], Awaitable[RefreshTokenRepo]],
    seeded_user: User,
) -> None:
    service = AuthService(user_repo, refresh_token_repo, password_reset_token_repo, service_client_repo)
    tokens = await service.login("user@example.com", "correct-horse")

    async def claim() -> bool:
        claim_refresh_tokens = await make_refresh_token_repo()
        claim_service = AuthService(user_repo, claim_refresh_tokens, password_reset_token_repo, service_client_repo)
        try:
            refresh_token = await claim_service._load_refresh_token(
                tokens.refresh_token,
                for_update=True,
            )
        except InvalidRefreshTokenError:
            return False
        return await claim_refresh_tokens.revoke(refresh_token)

    results = await asyncio.gather(claim(), claim(), return_exceptions=True)
    successes = [result for result in results if result is True]
    failures = [result for result in results if result is False]
    assert len(successes) == 1
    assert len(failures) == 1


async def test_expired_refresh_token_is_rejected(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    seeded_user: User,
) -> None:
    secret = "refresh-secret"
    refresh_token = RefreshToken(
        user_id=seeded_user.id,
        family_id=uuid4(),
        token_hash=RefreshTokenService.hash_secret(secret),
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
    )
    await refresh_token_repo.add(refresh_token)
    token = RefreshTokenService.build(refresh_token.id, secret)

    service = AuthService(user_repo, refresh_token_repo, password_reset_token_repo, service_client_repo)
    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(token)


async def test_rotation_keeps_family_id(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    seeded_user: User,
) -> None:
    service = AuthService(user_repo, refresh_token_repo, password_reset_token_repo, service_client_repo)
    tokens = await service.login("user@example.com", "correct-horse")
    original_id, _ = RefreshTokenService.parse(tokens.refresh_token)
    original = await refresh_token_repo.get_by_id(original_id)
    assert original is not None
    original_family_id = original.family_id

    rotated = await service.refresh(tokens.refresh_token)
    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)
    rotated_stored = await refresh_token_repo.get_by_id(rotated_id)
    assert rotated_stored is not None

    assert rotated_stored.family_id == original_family_id


async def test_login_mints_new_family_id(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    seeded_user: User,
) -> None:
    service = AuthService(user_repo, refresh_token_repo, password_reset_token_repo, service_client_repo)
    first = await service.login("user@example.com", "correct-horse")
    second = await service.login("user@example.com", "correct-horse")
    first_id, _ = RefreshTokenService.parse(first.refresh_token)
    second_id, _ = RefreshTokenService.parse(second.refresh_token)

    first_stored = await refresh_token_repo.get_by_id(first_id)
    second_stored = await refresh_token_repo.get_by_id(second_id)
    assert first_stored is not None
    assert second_stored is not None
    assert first_stored.family_id != second_stored.family_id


async def test_refresh_token_reuse_revokes_family(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    expire_refresh_reuse_grace: Callable[[], Awaitable[None]],
    seeded_user: User,
) -> None:
    service = AuthService(user_repo, refresh_token_repo, password_reset_token_repo, service_client_repo)
    tokens = await service.login("user@example.com", "correct-horse")
    original_id, _ = RefreshTokenService.parse(tokens.refresh_token)

    rotated = await service.refresh(tokens.refresh_token)
    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)

    await expire_refresh_reuse_grace()

    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(tokens.refresh_token)

    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(rotated.refresh_token)

    original_stored = await refresh_token_repo.get_by_id(original_id)
    rotated_stored = await refresh_token_repo.get_by_id(rotated_id)
    assert original_stored is not None
    assert rotated_stored is not None
    assert original_stored.revoked_at is not None
    assert rotated_stored.revoked_at is not None


async def test_reuse_with_corrupted_replacement_secret_revokes_family(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    seeded_user: User,
) -> None:
    service = AuthService(user_repo, refresh_token_repo, password_reset_token_repo, service_client_repo)
    tokens = await service.login("user@example.com", "correct-horse")
    original_id, _ = RefreshTokenService.parse(tokens.refresh_token)

    rotated = await service.refresh(tokens.refresh_token)
    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)

    original = await refresh_token_repo.get_by_id(original_id)
    assert original is not None
    assert original.replacement_secret is not None
    last_char = original.replacement_secret[-1]
    flipped = "A" if last_char != "A" else "B"
    original.replacement_secret = original.replacement_secret[:-1] + flipped

    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(tokens.refresh_token)

    original_stored = await refresh_token_repo.get_by_id(original_id)
    rotated_stored = await refresh_token_repo.get_by_id(rotated_id)
    assert original_stored is not None
    assert rotated_stored is not None
    assert original_stored.revoked_at is not None
    assert rotated_stored.revoked_at is not None


async def test_invalid_refresh_secret_does_not_revoke_family(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    seeded_user: User,
) -> None:
    service = AuthService(user_repo, refresh_token_repo, password_reset_token_repo, service_client_repo)
    tokens = await service.login("user@example.com", "correct-horse")
    rotated = await service.refresh(tokens.refresh_token)
    token_id, _ = RefreshTokenService.parse(tokens.refresh_token)
    forged = RefreshTokenService.build(token_id, "wrong-secret")

    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(forged)

    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)
    rotated_stored = await refresh_token_repo.get_by_id(rotated_id)
    assert rotated_stored is not None
    assert rotated_stored.revoked_at is None


async def test_expired_refresh_token_does_not_revoke_family(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
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
    await refresh_token_repo.add(expired)
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
    await refresh_token_repo.add(sibling)

    service = AuthService(user_repo, refresh_token_repo, password_reset_token_repo, service_client_repo)
    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(expired_token)

    sibling_stored = await refresh_token_repo.get_by_id(sibling_id)
    assert sibling_stored is not None
    assert sibling_stored.revoked_at is None
