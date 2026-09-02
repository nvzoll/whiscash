from typing import Protocol
from uuid import UUID

from app.db.models import PasswordResetToken, RefreshToken, ServiceClient, User


class UserRepo(Protocol):
    async def get_by_id(self, user_id: UUID) -> User | None: ...

    async def get_by_email(self, email: str) -> User | None: ...

    async def add(self, user: User) -> None: ...

    async def save(self, user: User) -> None: ...


class RefreshTokenRepo(Protocol):
    async def get_by_id(
        self,
        token_id: UUID,
        *,
        for_update: bool = False,
    ) -> RefreshToken | None: ...

    async def add(self, refresh_token: RefreshToken) -> None: ...

    async def revoke(
        self,
        refresh_token: RefreshToken,
        *,
        replaced_by: UUID | None = None,
        replacement_secret: str | None = None,
    ) -> bool: ...

    async def revoke_family(self, *, user_id: UUID, family_id: UUID) -> None: ...

    async def revoke_all_for_user(self, *, user_id: UUID) -> None: ...


class PasswordResetTokenRepo(Protocol):
    async def get_by_id(
        self,
        token_id: UUID,
        *,
        for_update: bool = False,
    ) -> PasswordResetToken | None: ...

    async def add(self, token: PasswordResetToken) -> None: ...

    async def mark_used(self, token: PasswordResetToken) -> bool: ...


class ServiceClientRepo(Protocol):
    async def get_by_key_hash(self, key_hash: str) -> ServiceClient | None: ...

    async def add(self, client: ServiceClient) -> None: ...
