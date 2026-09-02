from datetime import UTC, datetime, timedelta

from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings
from app.db.models import RefreshToken
from app.service.opaque_token import OpaqueToken

_fernet = Fernet(settings.refresh_token_key)


class RefreshTokenService:
    hash_secret = staticmethod(OpaqueToken.hash_secret)
    generate_secret = staticmethod(OpaqueToken.generate_secret)
    build = staticmethod(OpaqueToken.build)
    parse = staticmethod(OpaqueToken.parse)
    verify_secret = staticmethod(OpaqueToken.verify_secret)

    @staticmethod
    def enc_replacement_secret(secret: str) -> str:
        return _fernet.encrypt(secret.encode("utf-8")).decode("utf-8")

    @staticmethod
    def dec_replacement_secret(token: str) -> str | None:
        try:
            return _fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            return None

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
