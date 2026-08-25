import argparse
import asyncio
from datetime import UTC, datetime

from sqlalchemy import text

from database import SessionLocal, engine
from refresh_token_purge import purge_expired_refresh_tokens

DEFAULT_INTERVAL_SECONDS = 3600
DEFAULT_BATCH_SIZE = 1000
PURGE_LOCK_KEY = 748_293_104


async def run_purge_once(*, batch_size: int) -> int:
    async with SessionLocal() as session:
        locked = await session.scalar(
            text("SELECT pg_try_advisory_xact_lock(:key)"),
            {"key": PURGE_LOCK_KEY},
        )
        if not locked:
            return 0
        deleted = await purge_expired_refresh_tokens(session, limit=batch_size)
        await session.commit()
        return deleted


async def run_loop(*, interval_seconds: int, batch_size: int, once: bool) -> None:
    try:
        while True:
            deleted = await run_purge_once(batch_size=batch_size)
            print(
                f"{datetime.now(UTC).isoformat()} purged {deleted} expired refresh tokens",
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
