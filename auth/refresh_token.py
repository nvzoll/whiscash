from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest
from hmac import new as hmac_new
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from models import RefreshToken, User
from settings import settings


def hash_refresh_token_secret(secret: str) -> str:
    return sha256(secret.encode("utf-8")).hexdigest()


def derive_refresh_token_secret(token_id: UUID) -> str:
    return hmac_new(
        settings.jwt_secret.encode("utf-8"),
        token_id.bytes,
        sha256,
    ).hexdigest()


def build_refresh_token_value(token_id: UUID, secret: str) -> str:
    return f"{token_id}.{secret}"


def parse_refresh_token(token: str) -> tuple[UUID, str]:
    parts = token.split(".", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("invalid refresh token")

    try:
        token_id = UUID(parts[0])
    except ValueError as error:
        raise ValueError("invalid refresh token") from error

    return token_id, parts[1]


def verify_refresh_token_secret(secret: str, token_hash: str) -> bool:
    return compare_digest(hash_refresh_token_secret(secret), token_hash)


def is_refresh_token_active(
    refresh_token: RefreshToken,
    now: datetime | None = None,
) -> bool:
    if refresh_token.revoked_at is not None:
        return False

    if (expires_at := refresh_token.expires_at).tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    current_time = now or datetime.now(UTC)
    return expires_at > current_time


async def issue_refresh_token(
    session: AsyncSession,
    user: User,
) -> tuple[UUID, str]:
    token_id = uuid4()

    secret = derive_refresh_token_secret(token_id)
    refresh_token = RefreshToken(
        id=token_id,
        user_id=user.id,
        token_hash=hash_refresh_token_secret(secret),
        expires_at=datetime.now(UTC) + timedelta(days=settings.jwt_refresh_expires_days),
    )

    session.add(refresh_token)
    await session.flush()

    return token_id, build_refresh_token_value(token_id, secret)


def invalid_refresh_token() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
    )


async def get_refresh_token_for_user(
    session: AsyncSession,
    token: str,
) -> tuple[RefreshToken, User]:
    try:
        token_id, secret = parse_refresh_token(token)
    except ValueError as error:
        raise invalid_refresh_token() from error

    if (
        refresh_token := await session.get(
            RefreshToken,
            token_id,
            with_for_update=True,
            populate_existing=True,
        )
    ) is None:
        raise invalid_refresh_token()

    if not verify_refresh_token_secret(
        secret,
        refresh_token.token_hash,
    ):
        raise invalid_refresh_token()

    if (user := await session.get(User, refresh_token.user_id)) is None:
        raise invalid_refresh_token()

    return refresh_token, user


async def get_valid_refresh_token(
    session: AsyncSession,
    token: str,
) -> tuple[RefreshToken, User]:
    refresh_token, user = await get_refresh_token_for_user(session, token)
    if not is_refresh_token_active(refresh_token):
        raise invalid_refresh_token()

    return refresh_token, user


async def revoke_refresh_token(
    session: AsyncSession,
    refresh_token: RefreshToken,
) -> bool:
    now = datetime.now(UTC)

    result = await session.execute(
        update(RefreshToken)
        .where(
            RefreshToken.id == refresh_token.id,
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
        .returning(RefreshToken.id)
    )

    if result.scalar_one_or_none() is None:
        return False

    refresh_token.revoked_at = now
    return True


async def get_active_session_token(
    session: AsyncSession,
    session_id: UUID,
) -> RefreshToken | None:
    if (refresh_token := await session.get(RefreshToken, session_id)) is None:
        return None

    if not is_refresh_token_active(refresh_token):
        return None

    return refresh_token
