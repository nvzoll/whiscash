from typing import Annotated, Self

from fastapi import Depends

from app.controller.exceptions import to_http
from app.controller.validations import (
    AuthResponse,
    LoginRequest,
    ProfileUpdate,
    RefreshRequest,
    SignupRequest,
    UserResponse,
)
from app.db.models import User
from app.service.exceptions import DomainError
from app.service.service import AuthService, AuthTokens


class AuthController:
    def __init__(self, service: AuthService) -> None:
        self._service = service

    @classmethod
    async def new(
        cls,
        service: Annotated[AuthService, Depends(AuthService.new)],
    ) -> Self:
        return cls(service)

    async def signup(self, payload: SignupRequest) -> AuthResponse:
        try:
            tokens = await self._service.signup(
                str(payload.email),
                payload.password,
                payload.display_name,
            )
        except DomainError as error:
            raise to_http(error) from error
        return self._to_auth_response(tokens)

    async def login(self, payload: LoginRequest) -> AuthResponse:
        try:
            tokens = await self._service.login(str(payload.email), payload.password)
        except DomainError as error:
            raise to_http(error) from error
        return self._to_auth_response(tokens)

    async def refresh(self, payload: RefreshRequest) -> AuthResponse:
        try:
            tokens = await self._service.refresh(payload.refresh_token)
        except DomainError as error:
            raise to_http(error) from error
        return self._to_auth_response(tokens)

    async def logout(self, payload: RefreshRequest) -> None:
        try:
            await self._service.logout(payload.refresh_token)
        except DomainError as error:
            raise to_http(error) from error

    async def get_self(self, user: User) -> UserResponse:
        return UserResponse.model_validate(user)

    async def update_self(self, payload: ProfileUpdate, user: User) -> UserResponse:
        try:
            updated = await self._service.update_profile(
                user,
                payload.display_name,
                str(payload.photo_url) if payload.photo_url is not None else None,
            )
        except DomainError as error:
            raise to_http(error) from error

        return UserResponse.model_validate(updated)

    @staticmethod
    def _to_auth_response(tokens: AuthTokens) -> AuthResponse:
        return AuthResponse(
            access_token=tokens.access_token,
            refresh_token=tokens.refresh_token,
            expires_in=tokens.expires_in,
            user=UserResponse.model_validate(tokens.user),
        )
