import asyncio
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Annotated, Self
from uuid import UUID, uuid4

from fastapi import Depends

from app.core.config import settings
from app.db.models import PasswordResetToken, RefreshToken, ServiceClient, User
from app.repository.password_reset_tokens import SqlPasswordResetTokenRepo
from app.repository.protocols import PasswordResetTokenRepo, RefreshTokenRepo, ServiceClientRepo, UserRepo
from app.repository.refresh_tokens import SqlRefreshTokenRepo
from app.repository.service_clients import SqlServiceClientRepo
from app.repository.users import DuplicateEmailError, SqlUserRepo
from app.service.access_token import AccessTokenService
from app.service.exceptions import (
    InvalidAccessTokenError,
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
    InvalidRefreshTokenError,
    InvalidServiceKeyError,
    UserAlreadyExistsError,
)
from app.service.opaque_token import OpaqueToken
from app.service.password import PasswordService
from app.service.password_reset_token import PasswordResetTokenService
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
        password_reset_tokens: PasswordResetTokenRepo,
        service_clients: ServiceClientRepo,
    ) -> None:
        self._users = users
        self._refresh_tokens = refresh_tokens
        self._password_reset_tokens = password_reset_tokens
        self._service_clients = service_clients

    @classmethod
    async def new(
        cls,
        users: Annotated[UserRepo, Depends(SqlUserRepo.new)],
        refresh_tokens: Annotated[RefreshTokenRepo, Depends(SqlRefreshTokenRepo.new)],
        password_reset_tokens: Annotated[PasswordResetTokenRepo, Depends(SqlPasswordResetTokenRepo.new)],
        service_clients: Annotated[ServiceClientRepo, Depends(SqlServiceClientRepo.new)],
    ) -> Self:
        return cls(users, refresh_tokens, password_reset_tokens, service_clients)

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
        old_token = await self._load_refresh_token(refresh_token, for_update=True)

        if (user := await self._users.get_by_id(old_token.user_id)) is None:
            raise InvalidRefreshTokenError

        if old_token.revoked_at is not None:
            return await self._try_reuse_family(old_token, user)

        if not RefreshTokenService.is_active(old_token):
            raise InvalidRefreshTokenError

        rotated_id, rotated_secret = await self._issue_refresh_token(
            user,
            family_id=old_token.family_id,
        )

        await self._refresh_tokens.revoke(
            old_token,
            replaced_by=rotated_id,
            replacement_secret=RefreshTokenService.enc_replacement_secret(rotated_secret),
        )

        return AuthTokens(
            access_token=AccessTokenService.create(
                user.id,
                user.email,
                user.email_verified,
                rotated_id,
            ),
            refresh_token=RefreshTokenService.build(rotated_id, rotated_secret),
            expires_in=settings.jwt_expires_minutes * 60,
            user=user,
        )

    async def logout(self, token_str: str) -> None:
        rt = await self._load_refresh_token(token_str, for_update=True)
        if RefreshTokenService.is_active(rt) and not await self._refresh_tokens.revoke(rt):
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

    async def request_password_reset(self, email: str) -> str | None:
        if (user := await self._users.get_by_email(email)) is None:
            return None

        token_id = uuid4()
        secret = OpaqueToken.generate_secret()

        await self._password_reset_tokens.add(
            PasswordResetToken(
                id=token_id,
                user_id=user.id,
                token_hash=OpaqueToken.hash_secret(secret),
                expires_at=datetime.now(UTC) + timedelta(minutes=settings.password_reset_token_expires_minutes),
            )
        )

        return OpaqueToken.build(token_id, secret)

    async def confirm_password_reset(self, token: str, new_password: str) -> None:
        try:
            token_id, secret = OpaqueToken.parse(token)
        except ValueError as error:
            raise InvalidPasswordResetTokenError from error

        prt = await self._password_reset_tokens.get_by_id(token_id, for_update=True)
        if (
            prt is None
            or not OpaqueToken.verify_secret(secret, prt.token_hash)
            or not PasswordResetTokenService.is_active(prt)
        ):
            raise InvalidPasswordResetTokenError

        if (user := await self._users.get_by_id(prt.user_id)) is None:
            raise InvalidPasswordResetTokenError

        if not await self._password_reset_tokens.mark_used(prt):
            raise InvalidPasswordResetTokenError

        user.password_hash = await asyncio.to_thread(PasswordService.hash, new_password)
        if not user.email_verified:
            user.email_verified = True

        await self._users.save(user)
        await self._refresh_tokens.revoke_all_for_user(user_id=user.id)

    async def authenticate_service_client(self, key: str) -> ServiceClient:
        client = await self._service_clients.get_by_key_hash(OpaqueToken.hash_secret(key))
        if client is None or client.revoked_at is not None:
            raise InvalidServiceKeyError

        return client

    async def _issue_tokens(self, user: User) -> AuthTokens:
        session_id, secret = await self._issue_refresh_token(user)

        return AuthTokens(
            access_token=AccessTokenService.create(
                user.id,
                user.email,
                user.email_verified,
                session_id,
            ),
            refresh_token=RefreshTokenService.build(session_id, secret),
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
        secret = RefreshTokenService.generate_secret()
        session_family_id = family_id or uuid4()

        await self._refresh_tokens.add(
            RefreshToken(
                id=token_id,
                user_id=user.id,
                family_id=session_family_id,
                token_hash=RefreshTokenService.hash_secret(secret),
                expires_at=datetime.now(UTC) + timedelta(days=settings.jwt_refresh_expires_days),
                created_at=datetime.now(UTC),
            )
        )

        return token_id, secret

    async def _load_refresh_token(
        self,
        token: str,
        *,
        for_update: bool,
    ) -> RefreshToken:
        try:
            token_id, secret = RefreshTokenService.parse(token)
        except ValueError as error:
            raise InvalidRefreshTokenError from error

        if (
            rt := await self._refresh_tokens.get_by_id(
                token_id,
                for_update=for_update,
            )
        ) is None or not RefreshTokenService.verify_secret(secret, rt.token_hash):
            raise InvalidRefreshTokenError

        return rt

    async def _try_reuse_family(
        self,
        rt: RefreshToken,
        user: User,
    ) -> AuthTokens:
        if (
            RefreshTokenService.is_within_reuse_grace(rt.revoked_at)
            and rt.replaced_by is not None
            and rt.replacement_secret is not None
            and (successor := await self._refresh_tokens.get_by_id(rt.replaced_by)) is not None
            and RefreshTokenService.is_active(successor)
            and (secret := RefreshTokenService.dec_replacement_secret(rt.replacement_secret)) is not None
        ):
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
                user_id=rt.user_id,
                family_id=rt.family_id,
            )
            raise InvalidRefreshTokenError

    async def _has_active_session(self, session_id: UUID) -> bool:
        if (rt := await self._refresh_tokens.get_by_id(session_id)) is None:
            return False

        return RefreshTokenService.is_active(rt)
