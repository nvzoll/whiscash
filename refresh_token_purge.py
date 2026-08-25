from datetime import UTC, datetime

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from models import RefreshToken


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
            select(RefreshToken.id)
            .where(RefreshToken.expires_at <= current_time)
            .limit(limit)
        )
        token_ids = list(result.scalars().all())
        if not token_ids:
            break
        await session.execute(
            delete(RefreshToken).where(RefreshToken.id.in_(token_ids))
        )
        total += len(token_ids)
        if len(token_ids) < limit:
            break
    return total
