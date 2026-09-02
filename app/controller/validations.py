from datetime import datetime
from typing import Annotated, Any, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    BeforeValidator,
    ConfigDict,
    EmailStr,
    Field,
    HttpUrl,
    field_validator,
    model_validator,
)

from app.core.config import settings


def normalize_email(value: str) -> str:
    return value.strip().lower()


def _normalize_email_before(value: Any) -> Any:
    return normalize_email(value) if isinstance(value, str) else value


NormalizedEmail = Annotated[EmailStr, BeforeValidator(_normalize_email_before)]


def validate_password(value: str) -> str:
    pmin, pmax = settings.password_limits

    if len(value) < pmin:
        raise ValueError(f"password must contain at least {pmin} characters")
    if len(value.encode("utf-8")) > pmax:
        raise ValueError(f"password must not exceed {pmax} UTF-8 bytes")

    return value


def normalize_display_name(value: str) -> str:
    if not (normalized := value.strip()):
        raise ValueError("display_name must not be blank")

    return normalized


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SignupRequest(RequestModel):
    email: NormalizedEmail
    password: str
    display_name: str | None = Field(default=None, max_length=128)

    @field_validator("password")
    @classmethod
    def validate_password_field(cls, value: str) -> str:
        return validate_password(value)

    @field_validator("display_name", mode="before")
    @classmethod
    def normalize_display_name_field(cls, value: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        return normalize_display_name(value)


class LoginRequest(RequestModel):
    email: NormalizedEmail
    password: str


class ProfileUpdate(RequestModel):
    display_name: str | None = Field(default=None, max_length=128)
    photo_url: HttpUrl | None = Field(default=None, max_length=2048)

    @field_validator("display_name", mode="before")
    @classmethod
    def normalize_display_name_field(cls, value: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        return normalize_display_name(value)

    @model_validator(mode="after")
    def require_at_least_one_field(self) -> Self:
        if self.display_name is None and self.photo_url is None:
            raise ValueError("at least one of display_name or photo_url is required")
        return self


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    email: EmailStr
    display_name: str | None
    photo_url: HttpUrl | None
    email_verified: bool
    created_at: datetime


class AuthResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class RefreshRequest(RequestModel):
    refresh_token: str = Field(min_length=1)


class PasswordResetRequest(RequestModel):
    email: NormalizedEmail


class PasswordResetIssued(BaseModel):
    reset_token: str | None = None


class PasswordResetConfirm(RequestModel):
    token: str = Field(min_length=1)
    new_password: str

    @field_validator("new_password")
    @classmethod
    def validate_new_password_field(cls, value: str) -> str:
        return validate_password(value)
