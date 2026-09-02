import argparse
import asyncio
from uuid import uuid4

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.core.config import settings
from app.db.models import ServiceClient
from app.repository.service_clients import SqlServiceClientRepo
from app.service.opaque_token import OpaqueToken


async def create_service_key(name: str) -> str:
    key = OpaqueToken.generate_secret()
    engine = create_async_engine(settings.database_url)
    try:
        session_factory = async_sessionmaker(engine, expire_on_commit=False)
        async with session_factory() as session:
            await SqlServiceClientRepo(session).add(
                ServiceClient(id=uuid4(), name=name, key_hash=OpaqueToken.hash_secret(key))
            )
            await session.commit()
    finally:
        await engine.dispose()

    return key


def main() -> None:
    parser = argparse.ArgumentParser(description="Issue a new service-client API key")
    parser.add_argument("name", help="Human-readable name of the consumer service")
    args = parser.parse_args()

    key = asyncio.run(create_service_key(args.name))

    print(f"Service key for {args.name!r} (copy now, this is the only time it is shown):")
    print(key)


if __name__ == "__main__":
    main()
