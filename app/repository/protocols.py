from typing import Protocol
from uuid import UUID

from app.db.models import RefreshToken, User


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

    async def revoke(self, refresh_token: RefreshToken) -> bool: ...

    async def revoke_family(self, *, user_id: UUID, family_id: UUID) -> None: ...

    async def get_active_by_family(
        self,
        *,
        user_id: UUID,
        family_id: UUID,
    ) -> RefreshToken | None: ...
