from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_DELETE_EXPIRED_BATCH = text(
    """
    DELETE FROM refresh_token
    WHERE id IN (
        SELECT id FROM refresh_token
        WHERE expires_at <= :cutoff
        LIMIT :limit
    )
    RETURNING id
    """
)


async def purge_expired_refresh_tokens(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 1000,
) -> int:
    current_time = now or datetime.now(UTC)
    total = 0
    while True:
        result = await session.execute(
            _DELETE_EXPIRED_BATCH,
            {"cutoff": current_time, "limit": limit},
        )
        deleted_ids = result.scalars().all()
        total += len(deleted_ids)
        if len(deleted_ids) < limit:
            break
    return total
