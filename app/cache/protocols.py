from typing import Protocol
from uuid import UUID


class GraceCacheUnavailableError(Exception):
    pass


class GraceCache(Protocol):
    async def get(self, family_id: UUID) -> str | None: ...

    async def put(self, family_id: UUID, token: str, ttl_seconds: int) -> None: ...
