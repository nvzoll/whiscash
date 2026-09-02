from datetime import UTC, datetime

from app.db.models import PasswordResetToken


class PasswordResetTokenService:
    @staticmethod
    def is_active(prt: PasswordResetToken) -> bool:
        if prt.used_at is not None:
            return False

        return prt.expires_at > datetime.now(UTC)
