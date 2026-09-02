import asyncio
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

import pytest

from app.cache.protocols import GraceCache, GraceCacheUnavailableError
from app.db.models import RefreshToken, User
from app.repository.protocols import PasswordResetTokenRepo, RefreshTokenRepo, ServiceClientRepo, UserRepo
from app.service.exceptions import InvalidRefreshTokenError, RefreshUnavailableError
from app.service.refresh_token import RefreshTokenService
from app.service.service import AuthService


class MissGraceCache:
    """Grace cache that always misses, as if the entry had expired or been evicted."""

    async def get(self, family_id: UUID) -> str | None:
        return None

    async def put(self, family_id: UUID, token: str, ttl_seconds: int) -> None:
        pass


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
    auth_service: AuthService,
    seeded_user: User,
) -> None:
    tokens = await auth_service.login("user@example.com", "correct-horse")

    refresh_token = await auth_service._load_refresh_token(tokens.refresh_token, for_update=False)
    user = await auth_service._users.get_by_id(refresh_token.user_id)
    assert user is not None
    assert refresh_token.user_id == user.id
    assert user.email == "user@example.com"


async def test_issue_refresh_token_does_not_persist_secret(
    auth_service: AuthService,
    refresh_token_repo: RefreshTokenRepo,
    seeded_user: User,
) -> None:
    tokens = await auth_service.login("user@example.com", "correct-horse")
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
    auth_service: AuthService,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    grace_cache: GraceCache,
    make_refresh_token_repo: Callable[[], Awaitable[RefreshTokenRepo]],
    seeded_user: User,
) -> None:
    tokens = await auth_service.login("user@example.com", "correct-horse")

    async def claim() -> bool:
        claim_refresh_tokens = await make_refresh_token_repo()
        claim_service = AuthService(
            user_repo,
            claim_refresh_tokens,
            password_reset_token_repo,
            service_client_repo,
            grace_cache,
        )
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
    auth_service: AuthService,
    refresh_token_repo: RefreshTokenRepo,
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

    with pytest.raises(InvalidRefreshTokenError):
        await auth_service.refresh(token)


async def test_rotation_keeps_family_id(
    auth_service: AuthService,
    refresh_token_repo: RefreshTokenRepo,
    seeded_user: User,
) -> None:
    tokens = await auth_service.login("user@example.com", "correct-horse")
    original_id, _ = RefreshTokenService.parse(tokens.refresh_token)
    original = await refresh_token_repo.get_by_id(original_id)
    assert original is not None
    original_family_id = original.family_id

    rotated = await auth_service.refresh(tokens.refresh_token)
    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)
    rotated_stored = await refresh_token_repo.get_by_id(rotated_id)
    assert rotated_stored is not None

    assert rotated_stored.family_id == original_family_id


async def test_login_mints_new_family_id(
    auth_service: AuthService,
    refresh_token_repo: RefreshTokenRepo,
    seeded_user: User,
) -> None:
    first = await auth_service.login("user@example.com", "correct-horse")
    second = await auth_service.login("user@example.com", "correct-horse")
    first_id, _ = RefreshTokenService.parse(first.refresh_token)
    second_id, _ = RefreshTokenService.parse(second.refresh_token)

    first_stored = await refresh_token_repo.get_by_id(first_id)
    second_stored = await refresh_token_repo.get_by_id(second_id)
    assert first_stored is not None
    assert second_stored is not None
    assert first_stored.family_id != second_stored.family_id


async def test_refresh_token_reuse_revokes_family(
    auth_service: AuthService,
    refresh_token_repo: RefreshTokenRepo,
    expire_refresh_reuse_grace: Callable[[], Awaitable[None]],
    seeded_user: User,
) -> None:
    tokens = await auth_service.login("user@example.com", "correct-horse")
    original_id, _ = RefreshTokenService.parse(tokens.refresh_token)

    rotated = await auth_service.refresh(tokens.refresh_token)
    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)

    await expire_refresh_reuse_grace()

    with pytest.raises(InvalidRefreshTokenError):
        await auth_service.refresh(tokens.refresh_token)

    with pytest.raises(InvalidRefreshTokenError):
        await auth_service.refresh(rotated.refresh_token)

    original_stored = await refresh_token_repo.get_by_id(original_id)
    rotated_stored = await refresh_token_repo.get_by_id(rotated_id)
    assert original_stored is not None
    assert rotated_stored is not None
    assert original_stored.revoked_at is not None
    assert rotated_stored.revoked_at is not None


async def test_rapid_rotations_replay_t1_within_grace_returns_live_tokens(
    auth_service: AuthService,
    refresh_token_repo: RefreshTokenRepo,
    seeded_user: User,
) -> None:
    # 1. Login -> T1
    t1_tokens = await auth_service.login("user@example.com", "correct-horse")
    t1 = t1_tokens.refresh_token

    # 2. T1 -> T2
    t2_tokens = await auth_service.refresh(t1)
    t2 = t2_tokens.refresh_token

    # 3. T2 -> T3
    t3_tokens = await auth_service.refresh(t2)
    t3 = t3_tokens.refresh_token
    t3_id, _ = RefreshTokenService.parse(t3)

    # 4. Replay T1 within grace -> 200 with live T3 tokens
    replayed = await auth_service.refresh(t1)
    assert replayed.refresh_token == t3

    # Family intact: T3 must still be active
    t3_stored = await refresh_token_repo.get_by_id(t3_id)
    assert t3_stored is not None
    assert t3_stored.revoked_at is None
    assert RefreshTokenService.is_active(t3_stored)


async def test_replay_within_grace_cache_miss_returns_503_and_leaves_family_intact(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    seeded_user: User,
) -> None:
    service = AuthService(
        user_repo,
        refresh_token_repo,
        password_reset_token_repo,
        service_client_repo,
        MissGraceCache(),
    )
    tokens = await service.login("user@example.com", "correct-horse")
    rotated = await service.refresh(tokens.refresh_token)
    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)

    # Replay within grace with cache miss -> 503
    with pytest.raises(RefreshUnavailableError):
        await service.refresh(tokens.refresh_token)

    # Family intact: rotated token is not revoked
    rotated_stored = await refresh_token_repo.get_by_id(rotated_id)
    assert rotated_stored is not None
    assert rotated_stored.revoked_at is None


async def test_replay_within_grace_redis_unavailable_returns_503_and_leaves_family_intact(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    seeded_user: User,
) -> None:
    class BrokenGraceCache:
        async def get(self, family_id: UUID) -> str | None:
            raise GraceCacheUnavailableError("Redis connection lost")

        async def put(self, family_id: UUID, token: str, ttl_seconds: int) -> None:
            pass

    service = AuthService(
        user_repo,
        refresh_token_repo,
        password_reset_token_repo,
        service_client_repo,
        BrokenGraceCache(),
    )
    tokens = await service.login("user@example.com", "correct-horse")
    rotated = await service.refresh(tokens.refresh_token)
    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)

    with pytest.raises(RefreshUnavailableError):
        await service.refresh(tokens.refresh_token)

    rotated_stored = await refresh_token_repo.get_by_id(rotated_id)
    assert rotated_stored is not None
    assert rotated_stored.revoked_at is None


async def test_replay_after_logout_with_missing_cache_entry_returns_401(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    seeded_user: User,
) -> None:
    service = AuthService(
        user_repo,
        refresh_token_repo,
        password_reset_token_repo,
        service_client_repo,
        MissGraceCache(),
    )
    tokens = await service.login("user@example.com", "correct-horse")
    await service.logout(tokens.refresh_token)

    # The family is over, so the client must re-authenticate rather than retry.
    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(tokens.refresh_token)


async def test_replay_of_revoked_head_after_family_revocation_returns_401(
    user_repo: UserRepo,
    refresh_token_repo: RefreshTokenRepo,
    password_reset_token_repo: PasswordResetTokenRepo,
    service_client_repo: ServiceClientRepo,
    expire_refresh_reuse_grace: Callable[[], Awaitable[None]],
    seeded_user: User,
) -> None:
    service = AuthService(
        user_repo,
        refresh_token_repo,
        password_reset_token_repo,
        service_client_repo,
        MissGraceCache(),
    )
    tokens = await service.login("user@example.com", "correct-horse")
    rotated = await service.refresh(tokens.refresh_token)

    await expire_refresh_reuse_grace()

    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(tokens.refresh_token)

    # The head was revoked with the family; presenting it is not a retryable outage.
    with pytest.raises(InvalidRefreshTokenError):
        await service.refresh(rotated.refresh_token)


async def test_replay_within_grace_after_password_reset_returns_401(
    auth_service: AuthService,
    refresh_token_repo: RefreshTokenRepo,
    seeded_user: User,
) -> None:
    tokens = await auth_service.login("user@example.com", "correct-horse")
    t1 = tokens.refresh_token

    rotated = await auth_service.refresh(t1)
    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)

    reset_token = await auth_service.request_password_reset("user@example.com")
    assert reset_token is not None
    await auth_service.confirm_password_reset(reset_token, "new-password-is-here")

    stored_rotated = await refresh_token_repo.get_by_id(rotated_id)
    assert stored_rotated is not None
    assert stored_rotated.revoked_at is not None

    with pytest.raises(InvalidRefreshTokenError):
        await auth_service.refresh(t1)


async def test_invalid_refresh_secret_does_not_revoke_family(
    auth_service: AuthService,
    refresh_token_repo: RefreshTokenRepo,
    seeded_user: User,
) -> None:
    tokens = await auth_service.login("user@example.com", "correct-horse")
    rotated = await auth_service.refresh(tokens.refresh_token)
    token_id, _ = RefreshTokenService.parse(tokens.refresh_token)
    forged = RefreshTokenService.build(token_id, "wrong-secret")

    with pytest.raises(InvalidRefreshTokenError):
        await auth_service.refresh(forged)

    rotated_id, _ = RefreshTokenService.parse(rotated.refresh_token)
    rotated_stored = await refresh_token_repo.get_by_id(rotated_id)
    assert rotated_stored is not None
    assert rotated_stored.revoked_at is None


async def test_expired_refresh_token_does_not_revoke_family(
    auth_service: AuthService,
    refresh_token_repo: RefreshTokenRepo,
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

    with pytest.raises(InvalidRefreshTokenError):
        await auth_service.refresh(expired_token)

    sibling_stored = await refresh_token_repo.get_by_id(sibling_id)
    assert sibling_stored is not None
    assert sibling_stored.revoked_at is None
