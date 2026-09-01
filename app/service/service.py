import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from secrets import token_urlsafe
from uuid import UUID, uuid4

from app.core.config import settings
from app.db.models import RefreshToken, User
from app.repository.protocols import RefreshTokenRepo, UserRepo
from app.repository.users import DuplicateEmailError
from app.service.access_token import create_access_token, decode_access_token
from app.service.exceptions import (
    InvalidAccessTokenError,
    InvalidCredentialsError,
    InvalidRefreshTokenError,
    UserAlreadyExistsError,
)
from app.service.password import hash_password, verify_password
from app.service.refresh_token import (
    build_refresh_token_value,
    derive_refresh_token_secret,
    hash_refresh_token_secret,
    is_refresh_token_active,
    parse_refresh_token,
    verify_refresh_token_secret,
)


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

    async def signup(
        self,
        email: str,
        password: str,
        display_name: str | None,
    ) -> AuthTokens:
        password_hash = await asyncio.to_thread(hash_password, password)
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
            dummy = token_urlsafe(32)
            await asyncio.to_thread(hash_password, dummy)
            raise InvalidCredentialsError

        password_matches = await asyncio.to_thread(
            verify_password,
            password,
            user.password_hash,
        )
        if not password_matches:
            raise InvalidCredentialsError

        return await self._issue_tokens(user)

    async def refresh(self, refresh_token: str) -> AuthTokens:
        old_token, user = await self._resolve_refresh_token(refresh_token, for_update=True)
        session_id, rotated = await self._issue_refresh_token(user)
        if not await self._refresh_tokens.revoke(old_token):
            raise InvalidRefreshTokenError

        return AuthTokens(
            access_token=create_access_token(
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
            claims = decode_access_token(token)
        except ValueError as error:
            raise InvalidAccessTokenError from error
        user = await self._users.get_by_id(claims.sub)
        if user is None:
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
            access_token=create_access_token(
                user.id,
                user.email,
                user.email_verified,
                session_id,
            ),
            refresh_token=refresh_token,
            expires_in=settings.jwt_expires_minutes * 60,
            user=user,
        )

    async def _issue_refresh_token(self, user: User) -> tuple[UUID, str]:
        token_id = uuid4()
        secret = derive_refresh_token_secret(token_id)
        await self._refresh_tokens.add(
            RefreshToken(
                id=token_id,
                user_id=user.id,
                token_hash=hash_refresh_token_secret(secret),
                expires_at=datetime.now(UTC) + timedelta(days=settings.jwt_refresh_expires_days),
            )
        )
        return token_id, build_refresh_token_value(token_id, secret)

    async def _resolve_refresh_token(
        self,
        token: str,
        *,
        for_update: bool,
    ) -> tuple[RefreshToken, User]:
        try:
            token_id, secret = parse_refresh_token(token)
        except ValueError as error:
            raise InvalidRefreshTokenError from error

        refresh_token = await self._refresh_tokens.get_by_id(
            token_id,
            for_update=for_update,
        )
        if refresh_token is None:
            raise InvalidRefreshTokenError
        if not verify_refresh_token_secret(secret, refresh_token.token_hash):
            raise InvalidRefreshTokenError

        user = await self._users.get_by_id(refresh_token.user_id)
        if user is None:
            raise InvalidRefreshTokenError
        if not is_refresh_token_active(refresh_token):
            raise InvalidRefreshTokenError
        return refresh_token, user

    async def _has_active_session(self, session_id: UUID) -> bool:
        refresh_token = await self._refresh_tokens.get_by_id(session_id)
        if refresh_token is None:
            return False
        return is_refresh_token_active(refresh_token)
