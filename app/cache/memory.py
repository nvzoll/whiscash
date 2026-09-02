import time
from uuid import UUID


class InMemoryGraceCache:
    def __init__(self) -> None:
        self._store: dict[UUID, tuple[str, float]] = {}

    async def get(self, family_id: UUID) -> str | None:
        if family_id not in self._store:
            return None
        token, expires_at = self._store[family_id]
        if time.monotonic() >= expires_at:
            del self._store[family_id]
            return None
        return token

    async def put(self, family_id: UUID, token: str, ttl_seconds: int) -> None:
        self._store[family_id] = (token, time.monotonic() + ttl_seconds)
