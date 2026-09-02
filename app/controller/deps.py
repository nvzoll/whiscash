from typing import Annotated

from fastapi import Depends, Header
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.controller.controller import AuthController
from app.controller.exceptions import InvalidAccessTokenHTTP, InvalidServiceKeyHTTP, to_http
from app.db.models import ServiceClient, User
from app.service.exceptions import DomainError
from app.service.service import AuthService

bearer_scheme = HTTPBearer(auto_error=False)

CredentialsDependency = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(bearer_scheme),
]

AuthControllerDependency = Annotated[AuthController, Depends(AuthController.new)]


async def get_current_user(
    credentials: CredentialsDependency,
    service: Annotated[AuthService, Depends(AuthService.new)],
) -> User:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise InvalidAccessTokenHTTP()

    try:
        return await service.authenticate_access_token(credentials.credentials)
    except DomainError as error:
        raise to_http(error) from error


CurrentUserDependency = Annotated[User, Depends(get_current_user)]


async def get_current_service_client(
    service: Annotated[AuthService, Depends(AuthService.new)],
    x_service_key: Annotated[str | None, Header(alias="X-Service-Key")] = None,
) -> ServiceClient:
    if not x_service_key:
        raise InvalidServiceKeyHTTP()

    try:
        return await service.authenticate_service_client(x_service_key)
    except DomainError as error:
        raise to_http(error) from error


CurrentServiceClientDependency = Annotated[ServiceClient, Depends(get_current_service_client)]
