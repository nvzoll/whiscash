from datetime import UTC, datetime, timedelta

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

_CLEAR_REPLACEMENT_SECRET_BATCH = text(
    """
    UPDATE refresh_token
    SET replacement_secret = NULL, replaced_by = NULL
    WHERE id IN (
        SELECT id FROM refresh_token
        WHERE replacement_secret IS NOT NULL
          AND revoked_at <= :cutoff
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


async def clear_expired_replacement_secrets(
    session: AsyncSession,
    *,
    now: datetime | None = None,
    grace_seconds: int,
    limit: int = 1000,
) -> int:
    cutoff = (now or datetime.now(UTC)) - timedelta(seconds=grace_seconds)
    total = 0
    while True:
        result = await session.execute(
            _CLEAR_REPLACEMENT_SECRET_BATCH,
            {"cutoff": cutoff, "limit": limit},
        )
        cleared_ids = result.scalars().all()
        total += len(cleared_ids)
        if len(cleared_ids) < limit:
            break
    return total
