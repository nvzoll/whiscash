from datetime import UTC, datetime
from hashlib import sha256
from hmac import compare_digest
from hmac import new as hmac_new
from uuid import UUID

from app.core.config import settings
from app.db.models import RefreshToken


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
