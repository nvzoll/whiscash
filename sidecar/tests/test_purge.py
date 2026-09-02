from datetime import UTC, datetime, timedelta
from uuid import uuid4

from refresh_token_purge import clear_expired_replacement_secrets, purge_expired_refresh_tokens
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

_INSERT_TOKEN = text(
    """
    INSERT INTO refresh_token (
        id, user_id, family_id, token_hash, expires_at, revoked_at, created_at,
        replaced_by, replacement_secret
    )
    VALUES (
        :id, :user_id, :family_id, :token_hash, :expires_at, :revoked_at, :created_at,
        :replaced_by, :replacement_secret
    )
    """
)


async def _insert_token(
    session: AsyncSession,
    *,
    expires_at: datetime,
    revoked_at: datetime | None = None,
    replaced_by: str | None = None,
    replacement_secret: str | None = None,
) -> str:
    token_id = str(uuid4())
    family_id = str(uuid4())
    await session.execute(
        _INSERT_TOKEN,
        {
            "id": token_id,
            "user_id": str(uuid4()),
            "family_id": family_id,
            "token_hash": "hash",
            "expires_at": expires_at,
            "revoked_at": revoked_at,
            "created_at": datetime.now(UTC),
            "replaced_by": replaced_by,
            "replacement_secret": replacement_secret,
        },
    )
    return token_id


async def _existing_ids(session: AsyncSession) -> set[str]:
    result = await session.execute(text("SELECT id FROM refresh_token"))
    return set(result.scalars().all())


async def _replacement_fields(session: AsyncSession, token_id: str) -> tuple[str | None, str | None]:
    result = await session.execute(
        text("SELECT replaced_by, replacement_secret FROM refresh_token WHERE id = :id"),
        {"id": token_id},
    )
    replaced_by, replacement_secret = result.one()
    return replaced_by, replacement_secret


async def test_purge_expired_refresh_tokens_deletes_expired_only(
    session: AsyncSession,
) -> None:
    now = datetime.now(UTC)
    expired_id = await _insert_token(session, expires_at=now - timedelta(seconds=1))
    expired_revoked_id = await _insert_token(
        session,
        expires_at=now - timedelta(seconds=1),
        revoked_at=now - timedelta(hours=1),
    )
    active_id = await _insert_token(session, expires_at=now + timedelta(days=1))
    revoked_unexpired_id = await _insert_token(
        session,
        expires_at=now + timedelta(days=1),
        revoked_at=now,
    )
    await session.commit()

    deleted = await purge_expired_refresh_tokens(session, now=now, limit=1000)
    await session.commit()

    assert deleted == 2
    remaining = await _existing_ids(session)
    assert expired_id not in remaining
    assert expired_revoked_id not in remaining
    assert active_id in remaining
    assert revoked_unexpired_id in remaining


async def test_purge_expired_refresh_tokens_batches(session: AsyncSession) -> None:
    now = datetime.now(UTC)
    for _ in range(5):
        await _insert_token(session, expires_at=now - timedelta(seconds=1))
    active_id = await _insert_token(session, expires_at=now + timedelta(days=1))
    await session.commit()

    deleted = await purge_expired_refresh_tokens(session, now=now, limit=2)
    await session.commit()

    assert deleted == 5
    remaining = await _existing_ids(session)
    assert remaining == {active_id}


async def test_clear_expired_replacement_secrets_clears_past_grace_only(
    session: AsyncSession,
) -> None:
    now = datetime.now(UTC)
    past_grace_id = await _insert_token(
        session,
        expires_at=now + timedelta(days=1),
        revoked_at=now - timedelta(seconds=10),
        replaced_by=str(uuid4()),
        replacement_secret="enc-secret",
    )
    within_grace_id = await _insert_token(
        session,
        expires_at=now + timedelta(days=1),
        revoked_at=now,
        replaced_by=str(uuid4()),
        replacement_secret="enc-secret",
    )
    already_cleared_id = await _insert_token(
        session,
        expires_at=now + timedelta(days=1),
        revoked_at=now - timedelta(seconds=10),
    )
    await session.commit()

    cleared = await clear_expired_replacement_secrets(session, now=now, grace_seconds=2, limit=1000)
    await session.commit()

    assert cleared == 1
    assert await _replacement_fields(session, past_grace_id) == (None, None)
    replaced_by, replacement_secret = await _replacement_fields(session, within_grace_id)
    assert replaced_by is not None
    assert replacement_secret is not None
    assert await _replacement_fields(session, already_cleared_id) == (None, None)


async def test_clear_expired_replacement_secrets_batches(session: AsyncSession) -> None:
    now = datetime.now(UTC)
    for _ in range(5):
        await _insert_token(
            session,
            expires_at=now + timedelta(days=1),
            revoked_at=now - timedelta(seconds=10),
            replaced_by=str(uuid4()),
            replacement_secret="enc-secret",
        )
    await session.commit()

    cleared = await clear_expired_replacement_secrets(session, now=now, grace_seconds=2, limit=2)
    await session.commit()

    assert cleared == 5
