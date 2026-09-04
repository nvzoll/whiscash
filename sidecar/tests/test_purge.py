from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from conftest import insert_user
from purge import PURGE_LOCK_KEY, run_purge_once
from refresh_token_purge import purge_expired_refresh_tokens
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

_INSERT_REFRESH_TOKEN = text(
    """
    INSERT INTO refresh_token (
        id, user_id, family_id, token_hash, expires_at, revoked_at, created_at
    )
    VALUES (
        :id, :user_id, :family_id, :token_hash, :expires_at, :revoked_at, :created_at
    )
    """
)

_INSERT_RESET_TOKEN = text(
    """
    INSERT INTO password_reset_token (
        id, user_id, token_hash, expires_at, used_at, created_at
    )
    VALUES (
        :id, :user_id, :token_hash, :expires_at, :used_at, :created_at
    )
    """
)


async def _insert_refresh_token(
    conn: AsyncConnection,
    *,
    expires_at: datetime,
    revoked_at: datetime | None = None,
    user_id: str | None = None,
) -> str:
    if user_id is None:
        user_id = await insert_user(conn)
    token_id = str(uuid4())
    family_id = str(uuid4())
    await conn.execute(
        _INSERT_REFRESH_TOKEN,
        {
            "id": token_id,
            "user_id": user_id,
            "family_id": family_id,
            "token_hash": "hash",
            "expires_at": expires_at,
            "revoked_at": revoked_at,
            "created_at": datetime.now(UTC),
        },
    )
    await conn.commit()
    return token_id


async def _insert_reset_token(
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
        _INSERT_RESET_TOKEN,
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


async def _existing_refresh_ids(conn: AsyncConnection) -> set[str]:
    result = await conn.execute(text("SELECT id FROM refresh_token"))
    return {str(row[0]) for row in result.fetchall()}


async def _existing_reset_ids(conn: AsyncConnection) -> set[str]:
    result = await conn.execute(text("SELECT id FROM password_reset_token"))
    return {str(row[0]) for row in result.fetchall()}


async def test_purge_expired_refresh_tokens_deletes_expired_only(
    conn: AsyncConnection,
) -> None:
    now = datetime.now(UTC)
    expired_id = await _insert_refresh_token(conn, expires_at=now - timedelta(seconds=1))
    expired_revoked_id = await _insert_refresh_token(
        conn,
        expires_at=now - timedelta(seconds=1),
        revoked_at=now - timedelta(hours=1),
    )
    active_id = await _insert_refresh_token(conn, expires_at=now + timedelta(days=1))
    revoked_unexpired_id = await _insert_refresh_token(
        conn,
        expires_at=now + timedelta(days=1),
        revoked_at=now,
    )

    deleted = await purge_expired_refresh_tokens(conn, now=now, limit=1000)

    assert deleted == 2
    remaining = await _existing_refresh_ids(conn)
    assert expired_id not in remaining
    assert expired_revoked_id not in remaining
    assert active_id in remaining
    assert revoked_unexpired_id in remaining


async def test_purge_expired_refresh_tokens_batches(conn: AsyncConnection) -> None:
    now = datetime.now(UTC)
    user_id = await insert_user(conn)
    for _ in range(5):
        await _insert_refresh_token(conn, expires_at=now - timedelta(seconds=1), user_id=user_id)
    active_id = await _insert_refresh_token(conn, expires_at=now + timedelta(days=1), user_id=user_id)

    deleted = await purge_expired_refresh_tokens(conn, now=now, limit=2)

    assert deleted == 5
    remaining = await _existing_refresh_ids(conn)
    assert remaining == {active_id}


async def test_run_purge_once_two_connections_second_returns_skipped_sentinel(
    engine: AsyncEngine,
    conn: AsyncConnection,
) -> None:
    # First connection acquires the advisory lock
    locked = await conn.scalar(
        text("SELECT pg_try_advisory_lock(:key)"),
        {"key": PURGE_LOCK_KEY},
    )
    assert locked is True

    try:
        # Second connection attempts purge, should return None (skipped sentinel)
        async with engine.connect() as conn2:
            result = await run_purge_once(conn2, batch_size=1000)
            assert result is None
    finally:
        await conn.execute(
            text("SELECT pg_advisory_unlock(:key)"),
            {"key": PURGE_LOCK_KEY},
        )
        await conn.commit()

    # After lock release, run_purge_once succeeds
    async with engine.connect() as conn3:
        result = await run_purge_once(conn3, batch_size=1000)
        assert result is not None
        assert result.purged_refresh_tokens == 0
        assert result.purged_reset_tokens == 0


async def test_run_purge_once_per_batch_commit_on_mid_drain_failure(
    engine: AsyncEngine,
    conn: AsyncConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = datetime.now(UTC)
    user_id = await insert_user(conn)
    tokens = [
        await _insert_refresh_token(conn, expires_at=now - timedelta(seconds=1), user_id=user_id)
        for _ in range(4)
    ]

    real_execute = AsyncConnection.execute
    execute_count = 0

    async def mock_execute(self, statement, *args, **kwargs):
        nonlocal execute_count
        if "DELETE FROM refresh_token" in str(statement):
            execute_count += 1
            if execute_count > 1:
                raise SQLAlchemyError("simulated mid-drain batch failure")
        return await real_execute(self, statement, *args, **kwargs)

    monkeypatch.setattr(AsyncConnection, "execute", mock_execute)

    with pytest.raises(SQLAlchemyError, match="simulated mid-drain batch failure"):
        await run_purge_once(conn, batch_size=2)

    # The first batch of 2 tokens was committed and therefore deleted.
    # Check from a separate connection to prove per-batch commit was committed to the DB.
    async with engine.connect() as verify_conn:
        remaining = await _existing_refresh_ids(verify_conn)
        assert len(remaining) == 2
        deleted_count = len(set(tokens) - remaining)
        assert deleted_count == 2

    # The advisory lock should have been released in finally (verified from a separate connection)
    async with engine.connect() as verify_conn:
        lock_reacquired = await verify_conn.scalar(
            text("SELECT pg_try_advisory_lock(:key)"),
            {"key": PURGE_LOCK_KEY},
        )
        assert lock_reacquired is True
        await verify_conn.execute(
            text("SELECT pg_advisory_unlock(:key)"),
            {"key": PURGE_LOCK_KEY},
        )
        await verify_conn.commit()


async def test_run_purge_once_happy_path_deletes_across_both_tables(
    engine: AsyncEngine,
    conn: AsyncConnection,
) -> None:
    now = datetime.now(UTC)
    user_id = await insert_user(conn)

    # Refresh tokens
    expired_rt = await _insert_refresh_token(
        conn, expires_at=now - timedelta(seconds=1), user_id=user_id
    )
    active_rt = await _insert_refresh_token(
        conn, expires_at=now + timedelta(days=1), user_id=user_id
    )

    # Password reset tokens
    expired_pr = await _insert_reset_token(
        conn, expires_at=now - timedelta(seconds=1), user_id=user_id
    )
    used_pr = await _insert_reset_token(
        conn, expires_at=now + timedelta(days=1), used_at=now, user_id=user_id
    )
    active_pr = await _insert_reset_token(
        conn, expires_at=now + timedelta(days=1), user_id=user_id
    )

    result = await run_purge_once(conn, batch_size=1000)

    assert result is not None
    assert result.purged_refresh_tokens == 1
    assert result.purged_reset_tokens == 2

    remaining_rt = await _existing_refresh_ids(conn)
    assert remaining_rt == {active_rt}
    assert expired_rt not in remaining_rt

    remaining_pr = await _existing_reset_ids(conn)
    assert remaining_pr == {active_pr}
    assert expired_pr not in remaining_pr
    assert used_pr not in remaining_pr

    # Advisory lock should be free (verified from a separate connection)
    async with engine.connect() as verify_conn:
        lock_reacquired = await verify_conn.scalar(
            text("SELECT pg_try_advisory_lock(:key)"),
            {"key": PURGE_LOCK_KEY},
        )
        assert lock_reacquired is True
        await verify_conn.execute(
            text("SELECT pg_advisory_unlock(:key)"),
            {"key": PURGE_LOCK_KEY},
        )
        await verify_conn.commit()


async def test_run_purge_once_cleanup_failure_does_not_mask_purge_error(
    conn: AsyncConnection,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def failing_purge(*args, **kwargs):
        raise SQLAlchemyError("primary purge error")

    async def failing_rollback(self, *args, **kwargs):
        raise SQLAlchemyError("secondary cleanup error")

    monkeypatch.setattr("purge.purge_expired_refresh_tokens", failing_purge)
    monkeypatch.setattr(AsyncConnection, "rollback", failing_rollback)

    with pytest.raises(SQLAlchemyError, match="primary purge error"):
        await run_purge_once(conn, batch_size=1000)
