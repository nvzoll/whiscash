from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.controller.controller import AuthController
from app.controller.exceptions import InvalidAccessTokenHTTP, to_http
from app.db.models import User
from app.db.session import get_session
from app.repository.protocols import RefreshTokenRepo, UserRepo
from app.repository.refresh_tokens import SqlRefreshTokenRepo
from app.repository.users import SqlUserRepo
from app.service.exceptions import DomainError
from app.service.service import AuthService

bearer_scheme = HTTPBearer(auto_error=False)

CredentialsDependency = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(bearer_scheme),
]

SessionDependency = Annotated[AsyncSession, Depends(get_session)]


async def get_user_repo(session: SessionDependency) -> UserRepo:
    return SqlUserRepo(session)


async def get_refresh_token_repo(session: SessionDependency) -> RefreshTokenRepo:
    return SqlRefreshTokenRepo(session)


async def get_auth_service(
    users: Annotated[UserRepo, Depends(get_user_repo)],
    refresh_tokens: Annotated[RefreshTokenRepo, Depends(get_refresh_token_repo)],
) -> AuthService:
    return AuthService(users, refresh_tokens)


async def get_auth_controller(
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> AuthController:
    return AuthController(service)


AuthControllerDependency = Annotated[AuthController, Depends(get_auth_controller)]


async def get_current_user(
    credentials: CredentialsDependency,
    service: Annotated[AuthService, Depends(get_auth_service)],
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise InvalidAccessTokenHTTP()
    try:
        return await service.authenticate_access_token(credentials.credentials)
    except DomainError as error:
        raise to_http(error) from error


CurrentUserDependency = Annotated[User, Depends(get_current_user)]
