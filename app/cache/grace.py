from typing import Self
from uuid import UUID

from redis.asyncio import Redis
from redis.exceptions import RedisError

from app.cache.protocols import GraceCache, GraceCacheUnavailableError
from app.cache.redis import redis_client


class RedisGraceCache:
    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    @classmethod
    async def new(cls: type[Self]) -> GraceCache:
        return cls(redis_client)

    @staticmethod
    def _key(family_id: UUID) -> str:
        return f"grace:{family_id}"

    async def get(self, family_id: UUID) -> str | None:
        try:
            val = await self._redis.get(self._key(family_id))
            if isinstance(val, bytes):
                return val.decode()
            return val
        except RedisError as error:
            raise GraceCacheUnavailableError from error

    async def put(self, family_id: UUID, token: str, ttl_seconds: int) -> None:
        await self._redis.set(self._key(family_id), token, px=int(ttl_seconds * 1000))
