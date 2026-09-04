from datetime import UTC, datetime, timedelta
from uuid import uuid4

from conftest import insert_user
from password_reset_token_purge import purge_password_reset_tokens
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncConnection

_INSERT_TOKEN = text(
    """
    INSERT INTO password_reset_token (id, user_id, token_hash, expires_at, used_at, created_at)
    VALUES (:id, :user_id, :token_hash, :expires_at, :used_at, :created_at)
    """
)


async def _insert_token(
    conn: AsyncConnection,
    *,
    expires_at: datetime,
    used_at: datetime | None = None,
    user_id: str | None = None,
) -> str:
    if user_id is None:
        user_id = await insert_user(conn)
    token_id = str(uuid4())
    await conn.execute(
        _INSERT_TOKEN,
        {
            "id": token_id,
            "user_id": user_id,
            "token_hash": "hash",
            "expires_at": expires_at,
            "used_at": used_at,
            "created_at": datetime.now(UTC),
        },
    )
    await conn.commit()
    return token_id


async def _existing_ids(conn: AsyncConnection) -> set[str]:
    result = await conn.execute(text("SELECT id FROM password_reset_token"))
    return {str(row[0]) for row in result.fetchall()}


async def test_purge_password_reset_tokens_deletes_expired_and_used_only(
    conn: AsyncConnection,
) -> None:
    now = datetime.now(UTC)
    expired_id = await _insert_token(conn, expires_at=now - timedelta(seconds=1))
    used_id = await _insert_token(conn, expires_at=now + timedelta(days=1), used_at=now)
    active_id = await _insert_token(conn, expires_at=now + timedelta(days=1))

    deleted = await purge_password_reset_tokens(conn, now=now, limit=1000)

    assert deleted == 2
    remaining = await _existing_ids(conn)
    assert expired_id not in remaining
    assert used_id not in remaining
    assert active_id in remaining


async def test_purge_password_reset_tokens_batches(conn: AsyncConnection) -> None:
    now = datetime.now(UTC)
    user_id = await insert_user(conn)
    for _ in range(5):
        await _insert_token(conn, expires_at=now - timedelta(seconds=1), user_id=user_id)
    active_id = await _insert_token(conn, expires_at=now + timedelta(days=1), user_id=user_id)

    deleted = await purge_password_reset_tokens(conn, now=now, limit=2)

    assert deleted == 5
    remaining = await _existing_ids(conn)
    assert remaining == {active_id}
