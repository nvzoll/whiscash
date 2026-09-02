from datetime import UTC, datetime, timedelta

from app.core.config import settings
from app.db.models import RefreshToken
from app.service.opaque_token import OpaqueToken


class RefreshTokenService:
    hash_secret = staticmethod(OpaqueToken.hash_secret)
    generate_secret = staticmethod(OpaqueToken.generate_secret)
    build = staticmethod(OpaqueToken.build)
    parse = staticmethod(OpaqueToken.parse)
    verify_secret = staticmethod(OpaqueToken.verify_secret)

    @staticmethod
    def is_active(rt: RefreshToken) -> bool:
        if rt.revoked_at is not None:
            return False

        return rt.expires_at > datetime.now(UTC)

    @staticmethod
    def is_within_reuse_grace(revoked_at: datetime | None) -> bool:
        if revoked_at is None:
            return False

        elapsed = datetime.now(UTC) - revoked_at

        return elapsed <= timedelta(seconds=settings.jwt_refresh_reuse_grace_seconds)
