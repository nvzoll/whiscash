import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Self
from uuid import UUID, uuid4

from fastapi import Depends

from app.core.config import settings
from app.db.models import RefreshToken, User
from app.repository.protocols import RefreshTokenRepo, UserRepo
from app.repository.refresh_tokens import SqlRefreshTokenRepo
from app.repository.users import DuplicateEmailError, SqlUserRepo
from app.service.access_token import AccessTokenService
from app.service.exceptions import (
    InvalidAccessTokenError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    UserAlreadyExistsError,
)
from app.service.password import PasswordService
from app.service.refresh_token import RefreshTokenService

_DUMMY_HASH = PasswordService.hash("x" * 32)


@dataclass(frozen=True)
class AuthTokens:
    access_token: str
    refresh_token: str
    expires_in: int
    user: User


class AuthService:
    def __init__(
        self,
        users: UserRepo,
        refresh_tokens: RefreshTokenRepo,
    ) -> None:
        self._users = users
        self._refresh_tokens = refresh_tokens

    @classmethod
    async def new(
        cls,
        users: Annotated[UserRepo, Depends(SqlUserRepo.new)],
        refresh_tokens: Annotated[RefreshTokenRepo, Depends(SqlRefreshTokenRepo.new)],
    ) -> Self:
        return cls(users, refresh_tokens)

    async def signup(
        self,
        email: str,
        password: str,
        display_name: str | None,
    ) -> AuthTokens:
        password_hash = await asyncio.to_thread(PasswordService.hash, password)
        user = User(
            email=email,
            password_hash=password_hash,
            display_name=display_name,
            email_verified=False,
        )

        try:
            await self._users.add(user)
        except DuplicateEmailError as error:
            raise UserAlreadyExistsError from error

        return await self._issue_tokens(user)

    async def login(self, email: str, password: str) -> AuthTokens:
        if (user := await self._users.get_by_email(email)) is None:
            await asyncio.to_thread(PasswordService.verify, password, _DUMMY_HASH)
            raise InvalidCredentialsError

        password_matches = await asyncio.to_thread(
            PasswordService.verify,
            password,
            user.password_hash,
        )
        if not password_matches:
            raise InvalidCredentialsError

        return await self._issue_tokens(user)

    async def refresh(self, refresh_token: str) -> AuthTokens:
        old_token, user = await self._load_refresh_token(refresh_token, for_update=True)

        if old_token.revoked_at is not None:
            return await self._try_reuse_family(old_token, user)

        if not RefreshTokenService.is_active(old_token):
            raise InvalidRefreshTokenError

        session_id, rotated = await self._issue_refresh_token(
            user,
            family_id=old_token.family_id,
        )

        if not await self._refresh_tokens.revoke(old_token):
            rotated_id, _ = RefreshTokenService.parse(rotated)

            if (orphan := await self._refresh_tokens.get_by_id(rotated_id)) is not None:
                await self._refresh_tokens.revoke(orphan)

            if (
                reloaded := await self._refresh_tokens.get_by_id(
                    old_token.id,
                    for_update=True,
                )
            ) is None:
                raise InvalidRefreshTokenError

            return await self._try_reuse_family(reloaded, user)

        return AuthTokens(
            access_token=AccessTokenService.create(
                user.id,
                user.email,
                user.email_verified,
                session_id,
            ),
            refresh_token=rotated,
            expires_in=settings.jwt_expires_minutes * 60,
            user=user,
        )

    async def logout(self, refresh_token: str) -> None:
        old_token, _ = await self._resolve_refresh_token(refresh_token, for_update=True)
        if not await self._refresh_tokens.revoke(old_token):
            raise InvalidRefreshTokenError

    async def authenticate_access_token(self, token: str) -> User:
        try:
            claims = AccessTokenService.decode(token)
        except ValueError as error:
            raise InvalidAccessTokenError from error

        if (user := await self._users.get_by_id(claims.sub)) is None:
            raise InvalidAccessTokenError

        if not await self._has_active_session(claims.sid):
            raise InvalidAccessTokenError

        return user

    async def update_profile(
        self,
        user: User,
        display_name: str | None,
        photo_url: str | None,
    ) -> User:
        if display_name is not None:
            user.display_name = display_name
        if photo_url is not None:
            user.photo_url = photo_url

        await self._users.save(user)

        return user

    async def _issue_tokens(self, user: User) -> AuthTokens:
        session_id, refresh_token = await self._issue_refresh_token(user)
        return AuthTokens(
            access_token=AccessTokenService.create(
                user.id,
                user.email,
                user.email_verified,
                session_id,
            ),
            refresh_token=refresh_token,
            expires_in=settings.jwt_expires_minutes * 60,
            user=user,
        )

    async def _issue_refresh_token(
        self,
        user: User,
        *,
        family_id: UUID | None = None,
    ) -> tuple[UUID, str]:
        token_id = uuid4()
        secret = RefreshTokenService.derive_secret(token_id)
        session_family_id = family_id or uuid4()
        await self._refresh_tokens.add(
            RefreshToken(
                id=token_id,
                user_id=user.id,
                family_id=session_family_id,
                token_hash=RefreshTokenService.hash_secret(secret),
                expires_at=datetime.now(UTC) + timedelta(days=settings.jwt_refresh_expires_days),
            )
        )
        return token_id, RefreshTokenService.build(token_id, secret)

    async def _load_refresh_token(
        self,
        token: str,
        *,
        for_update: bool,
    ) -> tuple[RefreshToken, User]:
        try:
            token_id, secret = RefreshTokenService.parse(token)
        except ValueError as error:
            raise InvalidRefreshTokenError from error

        if (
            refresh_token := await self._refresh_tokens.get_by_id(
                token_id,
                for_update=for_update,
            )
        ) is None:
            raise InvalidRefreshTokenError

        if not RefreshTokenService.verify_secret(secret, refresh_token.token_hash):
            raise InvalidRefreshTokenError

        if (user := await self._users.get_by_id(refresh_token.user_id)) is None:
            raise InvalidRefreshTokenError

        return refresh_token, user

    async def _resolve_refresh_token(
        self,
        token: str,
        *,
        for_update: bool,
    ) -> tuple[RefreshToken, User]:
        refresh_token, user = await self._load_refresh_token(token, for_update=for_update)
        if not RefreshTokenService.is_active(refresh_token):
            raise InvalidRefreshTokenError
        return refresh_token, user

    async def _try_reuse_family(
        self,
        refresh_token: RefreshToken,
        user: User,
    ) -> AuthTokens:
        if (
            RefreshTokenService.is_within_reuse_grace(refresh_token.revoked_at)
            and (
                successor := await self._refresh_tokens.get_active_by_family(
                    user_id=refresh_token.user_id,
                    family_id=refresh_token.family_id,
                )
            ) is not None
        ):
            secret = RefreshTokenService.derive_secret(successor.id)
            return AuthTokens(
                access_token=AccessTokenService.create(
                    user.id,
                    user.email,
                    user.email_verified,
                    successor.id,
                ),
                refresh_token=RefreshTokenService.build(successor.id, secret),
                expires_in=settings.jwt_expires_minutes * 60,
                user=user,
            )
        else:
            await self._refresh_tokens.revoke_family(
                user_id=refresh_token.user_id,
                family_id=refresh_token.family_id,
            )
            raise InvalidRefreshTokenError

    async def _has_active_session(self, session_id: UUID) -> bool:
        if (refresh_token := await self._refresh_tokens.get_by_id(session_id)) is None:
            return False

        return RefreshTokenService.is_active(refresh_token)
