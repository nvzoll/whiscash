from datetime import UTC, datetime
from hashlib import sha256
from hmac import compare_digest
from hmac import new as hmac_new
from uuid import UUID

from app.core.config import settings
from app.db.models import RefreshToken


class RefreshTokenService:
    @staticmethod
    def hash_secret(secret: str) -> str:
        return sha256(secret.encode("utf-8")).hexdigest()

    @staticmethod
    def derive_secret(token_id: UUID) -> str:
        return hmac_new(
            settings.jwt_secret.encode("utf-8"),
            token_id.bytes,
            sha256,
        ).hexdigest()

    @staticmethod
    def build(token_id: UUID, secret: str) -> str:
        return f"{token_id}.{secret}"

    @staticmethod
    def parse(token: str) -> tuple[UUID, str]:
        parts = token.split(".", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError("invalid refresh token")

        try:
            token_id = UUID(parts[0])
        except ValueError as error:
            raise ValueError("invalid refresh token") from error

        return token_id, parts[1]

    @staticmethod
    def verify_secret(secret: str, token_hash: str) -> bool:
        return compare_digest(RefreshTokenService.hash_secret(secret), token_hash)

    @staticmethod
    def is_active(
        refresh_token: RefreshToken,
        now: datetime | None = None,
    ) -> bool:
        if refresh_token.revoked_at is not None:
            return False

        if (expires_at := refresh_token.expires_at).tzinfo is None:
            expires_at = expires_at.replace(tzinfo=UTC)

        current_time = now or datetime.now(UTC)
        return expires_at > current_time
