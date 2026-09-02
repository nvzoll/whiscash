from datetime import UTC, datetime

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_DELETE_EXPIRED_OR_USED_BATCH = text(
    """
    DELETE FROM password_reset_token
    WHERE id IN (
        SELECT id FROM password_reset_token
        WHERE expires_at <= :cutoff OR used_at IS NOT NULL
        LIMIT :limit
    )
    RETURNING id
    """
)


async def purge_password_reset_tokens(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    limit: int = 1000,
) -> int:
    current_time = now or datetime.now(UTC)
    total = 0
    while True:
        result = await session.execute(
            _DELETE_EXPIRED_OR_USED_BATCH,
            {"cutoff": current_time, "limit": limit},
        )
        deleted_ids = result.scalars().all()
        total += len(deleted_ids)
        if len(deleted_ids) < limit:
            break
    return total
