import secrets
from hashlib import sha256
from hmac import compare_digest
from uuid import UUID


class OpaqueToken:
    @staticmethod
    def generate_secret() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def hash_secret(secret: str) -> str:
        return sha256(secret.encode("utf-8")).hexdigest()

    @staticmethod
    def verify_secret(secret: str, token_hash: str) -> bool:
        return compare_digest(OpaqueToken.hash_secret(secret), token_hash)

    @staticmethod
    def build(token_id: UUID, secret: str) -> str:
        return f"{token_id}.{secret}"

    @staticmethod
    def parse(token: str) -> tuple[UUID, str]:
        parts = token.split(".", 1)
        if len(parts) != 2 or not parts[0] or not parts[1]:
            raise ValueError("invalid opaque token")

        try:
            token_id = UUID(parts[0])
        except ValueError as error:
            raise ValueError("invalid opaque token") from error

        return token_id, parts[1]
