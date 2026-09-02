from fastapi import HTTPException, status
from frozendict import frozendict

from app.service.exceptions import (
    DomainError,
    InvalidAccessTokenError,
    InvalidCredentialsError,
    InvalidPasswordResetTokenError,
    InvalidRefreshTokenError,
    InvalidServiceKeyError,
    PermissionDeniedError,
    TokenExpiredError,
    UserAlreadyExistsError,
    UserNotFoundError,
)


class BaseHTTPException(HTTPException):
    status_code: int = 500
    error: str = "internal_error"
    default_detail: str = "Internal server error"

    def __init__(
        self,
        detail: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        super().__init__(
            status_code=self.status_code,
            detail=detail or self.default_detail,
            headers=headers,
        )


class UserAlreadyExistsHTTP(BaseHTTPException):
    status_code = status.HTTP_409_CONFLICT
    error = "user_already_exists"
    default_detail = "Email is already registered"


class InvalidCredentialsHTTP(BaseHTTPException):
    status_code = status.HTTP_401_UNAUTHORIZED
    error = "invalid_credentials"
    default_detail = "Invalid email or password"


class InvalidAccessTokenHTTP(BaseHTTPException):
    status_code = status.HTTP_401_UNAUTHORIZED
    error = "invalid_access_token"
    default_detail = "Invalid or expired access token"

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(
            detail=detail,
            headers={"WWW-Authenticate": "Bearer"},
        )


class InvalidRefreshTokenHTTP(BaseHTTPException):
    status_code = status.HTTP_401_UNAUTHORIZED
    error = "invalid_refresh_token"
    default_detail = "Invalid or expired refresh token"


class TokenExpiredHTTP(BaseHTTPException):
    status_code = status.HTTP_401_UNAUTHORIZED
    error = "token_expired"
    default_detail = "Token expired"


class UserNotFoundHTTP(BaseHTTPException):
    status_code = status.HTTP_404_NOT_FOUND
    error = "user_not_found"
    default_detail = "User not found"


class PermissionDeniedHTTP(BaseHTTPException):
    status_code = status.HTTP_403_FORBIDDEN
    error = "permission_denied"
    default_detail = "Permission denied"


class InvalidPasswordResetTokenHTTP(BaseHTTPException):
    status_code = status.HTTP_400_BAD_REQUEST
    error = "invalid_password_reset_token"
    default_detail = "Invalid or expired reset token"


class InvalidServiceKeyHTTP(BaseHTTPException):
    status_code = status.HTTP_401_UNAUTHORIZED
    error = "invalid_service_key"
    default_detail = "Invalid or revoked service key"

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(
            detail=detail,
            headers={"WWW-Authenticate": "ServiceKey"},
        )


_DOMAIN_HTTP_MAP = frozendict(
    {
        UserAlreadyExistsError: UserAlreadyExistsHTTP,
        InvalidCredentialsError: InvalidCredentialsHTTP,
        InvalidAccessTokenError: InvalidAccessTokenHTTP,
        InvalidRefreshTokenError: InvalidRefreshTokenHTTP,
        TokenExpiredError: TokenExpiredHTTP,
        UserNotFoundError: UserNotFoundHTTP,
        PermissionDeniedError: PermissionDeniedHTTP,
        InvalidPasswordResetTokenError: InvalidPasswordResetTokenHTTP,
        InvalidServiceKeyError: InvalidServiceKeyHTTP,
    }
)


def to_http(error: DomainError) -> HTTPException:
    http_type = _DOMAIN_HTTP_MAP.get(type(error), BaseHTTPException)
    return http_type()
