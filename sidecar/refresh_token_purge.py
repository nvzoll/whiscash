from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

_DELETE_EXPIRED_BATCH = text(
    """
    DELETE FROM refresh_token
    WHERE id IN (
        SELECT id FROM refresh_token
        WHERE expires_at <= :cutoff
        LIMIT :limit
    )
    """
)


async def purge_expired_refresh_tokens(
    conn: AsyncConnection,
    *,
    now: datetime | None = None,
    limit: int = 1000,
) -> int:
    current_time = now or datetime.now(UTC)
    total = 0
    while True:
        result = await conn.execute(
            _DELETE_EXPIRED_BATCH,
            {"cutoff": current_time, "limit": limit},
        )
        await conn.commit()
        count = result.rowcount
        total += count
        if count < limit:
            break
    return total
