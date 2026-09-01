from typing import Annotated

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.controller.controller import AuthController
from app.controller.exceptions import InvalidAccessTokenHTTP, to_http
from app.db.models import User
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
