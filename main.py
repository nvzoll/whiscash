import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Annotated, Any
from uuid import UUID, uuid4

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import (
    BaseModel,
    ConfigDict,
    EmailStr,
    Field,
    HttpUrl,
    ValidationError,
    field_validator,
)
from sqlalchemy import Boolean, DateTime, String, Uuid, false, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://auth:auth@localhost:5432/auth",
)
JWT_SECRET = os.getenv("JWT_SECRET", "development-only-change-me-32-bytes")
JWT_ALGORITHM = "HS256"
JWT_EXPIRES_MINUTES = int(os.getenv("JWT_EXPIRES_MINUTES", "60"))

if JWT_EXPIRES_MINUTES <= 0:
    raise ValueError("JWT_EXPIRES_MINUTES must be positive")

engine = create_async_engine(DATABASE_URL)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
bearer_scheme = HTTPBearer(auto_error=False)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "user"

    id: Mapped[UUID] = mapped_column(Uuid, primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(60))
    display_name: Mapped[str | None] = mapped_column(String(128), default=None)
    photo_url: Mapped[str | None] = mapped_column(String(2048), default=None)
    email_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=false(),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


def normalize_email(value: str) -> str:
    return value.strip().lower()


def validate_password(value: str) -> str:
    if len(value) < 8:
        raise ValueError("password must contain at least 8 characters")
    if len(value.encode("utf-8")) > 72:
        raise ValueError("password must not exceed 72 UTF-8 bytes")
    return value


def normalize_display_name(value: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError("display_name must not be blank")
    return normalized


class RequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SignupRequest(RequestModel):
    email: EmailStr
    password: str
    display_name: str | None = Field(default=None, max_length=128)
    photo_url: HttpUrl | None = Field(default=None, max_length=2048)

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email_field(cls, value: Any) -> Any:
        return normalize_email(value) if isinstance(value, str) else value

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
    email: EmailStr
    password: str

    @field_validator("email", mode="before")
    @classmethod
    def normalize_email_field(cls, value: Any) -> Any:
        return normalize_email(value) if isinstance(value, str) else value

    @field_validator("password")
    @classmethod
    def validate_password_field(cls, value: str) -> str:
        return validate_password(value)


class ProfileUpdate(RequestModel):
    display_name: str | None = Field(default=None, max_length=128)
    photo_url: HttpUrl | None = Field(default=None, max_length=2048)

    @field_validator("display_name", mode="before")
    @classmethod
    def normalize_display_name_field(cls, value: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        return normalize_display_name(value)


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
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class TokenClaims(BaseModel):
    sub: UUID
    email: EmailStr
    email_verified: bool
    iat: int
    exp: int


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8"),
        )
    except ValueError:
        return False


def create_access_token(
    user_id: UUID,
    email: str,
    email_verified: bool,
    expires_minutes: int = JWT_EXPIRES_MINUTES,
) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "email": email,
        "email_verified": email_verified,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> TokenClaims:
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM],
            options={
                "require": ["sub", "email", "email_verified", "iat", "exp"],
            },
        )
        return TokenClaims.model_validate(payload)
    except (jwt.InvalidTokenError, ValidationError) as error:
        raise ValueError("invalid or expired access token") from error


def create_auth_response(user: User) -> AuthResponse:
    return AuthResponse(
        access_token=create_access_token(
            user.id,
            user.email,
            user.email_verified,
        ),
        expires_in=JWT_EXPIRES_MINUTES * 60,
        user=UserResponse.model_validate(user),
    )


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session


SessionDependency = Annotated[AsyncSession, Depends(get_session)]
CredentialsDependency = Annotated[
    HTTPAuthorizationCredentials | None,
    Depends(bearer_scheme),
]


async def get_current_user(
    credentials: CredentialsDependency,
    session: SessionDependency,
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired access token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise unauthorized
    try:
        claims = decode_access_token(credentials.credentials)
    except ValueError as error:
        raise unauthorized from error
    user = await session.get(User, claims.sub)
    if user is None:
        raise unauthorized
    return user


CurrentUserDependency = Annotated[User, Depends(get_current_user)]


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(title="FastAPI Postgres JWT Auth", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post(
    "/auth/signup",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
)
async def signup(
    payload: SignupRequest,
    session: SessionDependency,
) -> AuthResponse:
    password_hash = await run_in_threadpool(hash_password, payload.password)
    user = User(
        email=str(payload.email),
        password_hash=password_hash,
        display_name=payload.display_name,
        photo_url=str(payload.photo_url) if payload.photo_url is not None else None,
        email_verified=False,
    )
    session.add(user)
    try:
        await session.commit()
        await session.refresh(user)
    except IntegrityError as error:
        await session.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email is already registered",
        ) from error
    return create_auth_response(user)


@app.post("/auth/login", response_model=AuthResponse)
async def login(
    payload: LoginRequest,
    session: SessionDependency,
) -> AuthResponse:
    user = await session.scalar(select(User).where(User.email == str(payload.email)))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    password_matches = await run_in_threadpool(
        verify_password,
        payload.password,
        user.password_hash,
    )
    if not password_matches:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )
    return create_auth_response(user)


@app.get("/auth/me", response_model=UserResponse)
async def get_me(user: CurrentUserDependency) -> UserResponse:
    return UserResponse.model_validate(user)


@app.patch("/auth/me", response_model=UserResponse)
async def update_me(
    payload: ProfileUpdate,
    user: CurrentUserDependency,
    session: SessionDependency,
) -> UserResponse:
    if not payload.model_fields_set:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail="At least one profile field is required",
        )
    if "display_name" in payload.model_fields_set:
        user.display_name = payload.display_name
    if "photo_url" in payload.model_fields_set:
        user.photo_url = (
            str(payload.photo_url) if payload.photo_url is not None else None
        )
    await session.commit()
    await session.refresh(user)
    return UserResponse.model_validate(user)
