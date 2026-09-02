import argparse
import asyncio
import secrets
from hashlib import sha256
from uuid import uuid4

from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", frozen=True)

    database_url: str


async def _create(name: str) -> str:
    key = secrets.token_urlsafe(32)
    key_hash = sha256(key.encode("utf-8")).hexdigest()

    engine = create_async_engine(Settings().database_url)
    try:
        async with engine.begin() as conn:
            await conn.execute(
                text("INSERT INTO service_client (id, name, key_hash) VALUES (:id, :name, :key_hash)"),
                {"id": uuid4(), "name": name, "key_hash": key_hash},
            )
    finally:
        await engine.dispose()

    return key


def new(args: argparse.Namespace) -> None:
    key = asyncio.run(_create(args.name))

    print(f"Service key for {args.name!r} (copy now, this is the only time it is shown):")
    print(key)


def register(subparsers: argparse._SubParsersAction) -> None:
    group = subparsers.add_parser("service-key", help="Manage service-client API keys")
    actions = group.add_subparsers(dest="action", required=True)

    new_parser = actions.add_parser("new", help="Issue a new service-client API key")
    new_parser.add_argument("name", help="Human-readable name of the consumer service")
    new_parser.set_defaults(func=new)
