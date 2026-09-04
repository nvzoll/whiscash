import argparse
import asyncio
import sys
from dataclasses import dataclass
from datetime import UTC, datetime

from password_reset_token_purge import purge_password_reset_tokens
from pydantic_settings import BaseSettings, SettingsConfigDict
from refresh_token_purge import purge_expired_refresh_tokens
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

DEFAULT_INTERVAL_SECONDS = 300
DEFAULT_BATCH_SIZE = 1000
PURGE_LOCK_KEY = 748_293_104


class PurgeSettings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", frozen=True)

    database_url: str


settings = PurgeSettings()
engine = create_async_engine(settings.database_url, poolclass=NullPool)


@dataclass(frozen=True)
class PurgeResult:
    purged_refresh_tokens: int
    purged_reset_tokens: int


async def run_purge_once(
    conn: AsyncConnection,
    *,
    batch_size: int,
) -> PurgeResult | None:
    locked = await conn.scalar(
        text("SELECT pg_try_advisory_lock(:key)"),
        {"key": PURGE_LOCK_KEY},
    )
    if not locked:
        return None
    success = False
    try:
        deleted = await purge_expired_refresh_tokens(conn, limit=batch_size)
        deleted_reset_tokens = await purge_password_reset_tokens(conn, limit=batch_size)
        success = True
        return PurgeResult(
            purged_refresh_tokens=deleted,
            purged_reset_tokens=deleted_reset_tokens,
        )
    finally:
        try:
            await conn.rollback()
        except Exception:
            if success:
                raise
        try:
            await conn.execute(
                text("SELECT pg_advisory_unlock(:key)"),
                {"key": PURGE_LOCK_KEY},
            )
            await conn.commit()
        except Exception:
            if success:
                raise


async def run_loop(*, interval_seconds: int, batch_size: int, once: bool) -> None:
    try:
        while True:
            try:
                async with engine.connect() as conn:
                    result = await run_purge_once(
                        conn,
                        batch_size=batch_size,
                    )
                if result is None:
                    print(
                        f"{datetime.now(UTC).isoformat()} skipped: another purge holds the lock",
                        flush=True,
                    )
                else:
                    print(
                        f"{datetime.now(UTC).isoformat()} purged {result.purged_refresh_tokens} expired refresh tokens, "
                        f"purged {result.purged_reset_tokens} expired/used password reset tokens",
                        flush=True,
                    )
            except SQLAlchemyError as error:
                print(
                    f"{datetime.now(UTC).isoformat()} purge failed: {error}",
                    file=sys.stderr,
                    flush=True,
                )
            if once:
                return
            await asyncio.sleep(interval_seconds)
    finally:
        await engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="Purge expired refresh tokens")
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=DEFAULT_INTERVAL_SECONDS,
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=DEFAULT_BATCH_SIZE,
    )
    parser.add_argument(
        "--once",
        action="store_true",
    )
    args = parser.parse_args()
    if args.interval_seconds <= 0:
        parser.error("--interval-seconds must be greater than 0")
    if args.batch_size <= 0:
        parser.error("--batch-size must be greater than 0")
    asyncio.run(
        run_loop(
            interval_seconds=args.interval_seconds,
            batch_size=args.batch_size,
            once=args.once,
        )
    )


if __name__ == "__main__":
    main()
