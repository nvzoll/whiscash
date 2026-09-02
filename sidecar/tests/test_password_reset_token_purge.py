from datetime import UTC, datetime, timedelta
from uuid import uuid4

from password_reset_token_purge import purge_password_reset_tokens
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_INSERT_TOKEN = text(
    """
    INSERT INTO password_reset_token (id, user_id, token_hash, expires_at, used_at, created_at)
    VALUES (:id, :user_id, :token_hash, :expires_at, :used_at, :created_at)
    """
)


async def _insert_token(
    session: AsyncSession,
    *,
    expires_at: datetime,
    used_at: datetime | None = None,
) -> str:
    token_id = str(uuid4())
    await session.execute(
        _INSERT_TOKEN,
        {
            "id": token_id,
            "user_id": str(uuid4()),
            "token_hash": "hash",
            "expires_at": expires_at,
            "used_at": used_at,
            "created_at": datetime.now(UTC),
        },
    )
    return token_id


async def _existing_ids(session: AsyncSession) -> set[str]:
    result = await session.execute(text("SELECT id FROM password_reset_token"))
    return set(result.scalars().all())


async def test_purge_password_reset_tokens_deletes_expired_and_used_only(
    session: AsyncSession,
) -> None:
    now = datetime.now(UTC)
    expired_id = await _insert_token(session, expires_at=now - timedelta(seconds=1))
    used_id = await _insert_token(session, expires_at=now + timedelta(days=1), used_at=now)
    active_id = await _insert_token(session, expires_at=now + timedelta(days=1))
    await session.commit()

    deleted = await purge_password_reset_tokens(session, now=now, limit=1000)
    await session.commit()

    assert deleted == 2
    remaining = await _existing_ids(session)
    assert expired_id not in remaining
    assert used_id not in remaining
    assert active_id in remaining


async def test_purge_password_reset_tokens_batches(session: AsyncSession) -> None:
    now = datetime.now(UTC)
    for _ in range(5):
        await _insert_token(session, expires_at=now - timedelta(seconds=1))
    active_id = await _insert_token(session, expires_at=now + timedelta(days=1))
    await session.commit()

    deleted = await purge_password_reset_tokens(session, now=now, limit=2)
    await session.commit()

    assert deleted == 5
    remaining = await _existing_ids(session)
    assert remaining == {active_id}
