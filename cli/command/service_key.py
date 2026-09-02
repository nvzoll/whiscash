import argparse
import asyncio
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from hashlib import sha256
from uuid import UUID, uuid4

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", frozen=True)

    database_url: str


@asynccontextmanager
async def _connect() -> AsyncIterator[AsyncConnection]:
    engine = create_async_engine(Settings().database_url)
    try:
        async with engine.begin() as conn:
            yield conn
    finally:
        await engine.dispose()


async def _create(name: str) -> str:
    key = secrets.token_urlsafe(32)
    key_hash = sha256(key.encode("utf-8")).hexdigest()

    async with _connect() as conn:
        await conn.execute(
            text("INSERT INTO service_client (id, name, key_hash) VALUES (:id, :name, :key_hash)"),
            {"id": uuid4(), "name": name, "key_hash": key_hash},
        )

    return key


async def _revoke(name: str) -> UUID:
    async with _connect() as conn:
        revoked = await conn.execute(
            text("UPDATE service_client SET revoked_at = now() WHERE name = :name AND revoked_at IS NULL RETURNING id"),
            {"name": name},
        )
        if (client_id := revoked.scalar_one_or_none()) is not None:
            return client_id

        existing = await conn.execute(
            text("SELECT count(*) FROM service_client WHERE name = :name"),
            {"name": name},
        )
        if existing.scalar_one():
            raise SystemExit(f"no active key named {name!r} (already revoked)")

        raise SystemExit(f"no key named {name!r}")


async def _list() -> list[tuple[UUID, str, datetime, datetime | None]]:
    async with _connect() as conn:
        result = await conn.execute(
            text("SELECT id, name, created_at, revoked_at FROM service_client ORDER BY name, created_at")
        )
        return list(result.tuples())


def new(args: argparse.Namespace) -> None:
    try:
        key = asyncio.run(_create(args.name))
    except IntegrityError as error:
        raise SystemExit(f"a live key named {args.name!r} already exists; revoke it first") from error

    print(f"Service key for {args.name!r} (copy now, this is the only time it is shown):")
    print(key)


def revoke(args: argparse.Namespace) -> None:
    client_id = asyncio.run(_revoke(args.name))

    print(f"revoked {args.name!r} ({client_id})")


def list_keys(_args: argparse.Namespace) -> None:
    rows = asyncio.run(_list())
    if not rows:
        print("no service keys")
        return

    width = max(len(name) for _, name, _, _ in rows)
    for client_id, name, created_at, revoked_at in rows:
        status = "active" if revoked_at is None else f"revoked {revoked_at:%Y-%m-%d}"
        print(f"{client_id}  {name:<{width}}  created {created_at:%Y-%m-%d}  {status}")


def register(subparsers: argparse._SubParsersAction) -> None:
    group = subparsers.add_parser("service-key", help="Manage service-client API keys")
    actions = group.add_subparsers(dest="action", required=True)

    new_parser = actions.add_parser("new", help="Issue a new service-client API key")
    new_parser.add_argument("name", help="Human-readable name of the consumer service")
    new_parser.set_defaults(func=new)

    revoke_parser = actions.add_parser("revoke", help="Revoke the active service-client API key with this name")
    revoke_parser.add_argument("name", help="Name of the consumer service whose key should be pulled")
    revoke_parser.set_defaults(func=revoke)

    list_parser = actions.add_parser("list", help="List service-client API keys")
    list_parser.set_defaults(func=list_keys)
