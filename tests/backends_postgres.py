import os
import subprocess
from pathlib import Path
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from testcontainers.community.postgres import PostgresContainer

from app.db.models import PasswordResetToken, RefreshToken, ServiceClient, User
from app.repository.password_reset_tokens import SqlPasswordResetTokenRepo
from app.repository.refresh_tokens import SqlRefreshTokenRepo
from app.repository.service_clients import SqlServiceClientRepo
from app.repository.users import DuplicateEmailError, SqlUserRepo

REPO_ROOT = Path(__file__).resolve().parent.parent


def start_container() -> PostgresContainer:
    container = PostgresContainer("postgres:16-alpine", driver="asyncpg")
    container.start()
    return container


def async_url(container: PostgresContainer) -> str:
    return container.get_connection_url()


def run_migrations(database_url: str) -> None:
    subprocess.run(
        ["uv", "run", "alembic", "upgrade", "head"],
        cwd=REPO_ROOT,
        env={**os.environ, "DATABASE_URL": database_url},
        check=True,
    )


async def truncate_all(session: AsyncSession) -> None:
    await session.execute(text('TRUNCATE TABLE "user" RESTART IDENTITY CASCADE'))
    await session.execute(text("TRUNCATE TABLE service_client RESTART IDENTITY CASCADE"))
    await session.commit()


class AutoCommitUserRepo(SqlUserRepo):
    async def add(self, user: User) -> None:
        try:
            await super().add(user)
        except DuplicateEmailError:
            await self._session.rollback()
            raise
        await self._session.commit()

    async def save(self, user: User) -> None:
        await super().save(user)
        await self._session.commit()


class AutoCommitRefreshTokenRepo(SqlRefreshTokenRepo):
    async def add(self, refresh_token: RefreshToken) -> None:
        await super().add(refresh_token)
        await self._session.commit()

    async def revoke(
        self,
        refresh_token: RefreshToken,
        *,
        replaced_by: UUID | None = None,
        replacement_secret: str | None = None,
    ) -> bool:
        result = await super().revoke(
            refresh_token,
            replaced_by=replaced_by,
            replacement_secret=replacement_secret,
        )
        await self._session.commit()
        return result

    async def revoke_family(self, *, user_id: UUID, family_id: UUID) -> None:
        await super().revoke_family(user_id=user_id, family_id=family_id)
        await self._session.commit()

    async def revoke_all_for_user(self, *, user_id: UUID) -> None:
        await super().revoke_all_for_user(user_id=user_id)
        await self._session.commit()


class AutoCommitPasswordResetTokenRepo(SqlPasswordResetTokenRepo):
    async def add(self, token: PasswordResetToken) -> None:
        await super().add(token)
        await self._session.commit()

    async def mark_used(self, token: PasswordResetToken) -> bool:
        result = await super().mark_used(token)
        await self._session.commit()
        return result


class AutoCommitServiceClientRepo(SqlServiceClientRepo):
    async def add(self, client: ServiceClient) -> None:
        await super().add(client)
        await self._session.commit()
