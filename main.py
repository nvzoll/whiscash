from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from hmac import compare_digest
from secrets import token_urlsafe
from typing import Annotated
from uuid import UUID, uuid4

import bcrypt
import jwt
from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import ValidationError
from sqlalchemy import select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from models import RefreshToken, User
from schemas import (
    AuthResponse,
    LoginRequest,
    ProfileUpdate,
    RefreshRequest,
    SignupRequest,
    TokenClaims,
    UserResponse,
)
from settings import settings

engine = create_async_engine(settings.database_url)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False)
bearer_scheme = HTTPBearer(auto_error=False)


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
    expires_minutes: int = settings.jwt_expires_minutes,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "email": email,
        "email_verified": email_verified,
        "typ": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=expires_minutes)).timestamp()),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> TokenClaims:
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret,
            algorithms=[settings.jwt_algorithm],
            options={
                "require": ["sub", "email", "email_verified", "typ", "iat", "exp"],
            },
        )
        return TokenClaims.model_validate(payload)
    except (jwt.InvalidTokenError, ValidationError) as error:
        raise ValueError("invalid or expired access token") from error


def hash_refresh_token_secret(secret: str) -> str:
    return sha256(secret.encode("utf-8")).hexdigest()


def build_refresh_token_value(token_id: UUID, secret: str) -> str:
    return f"{token_id}.{secret}"


def parse_refresh_token(token: str) -> tuple[UUID, str]:
    parts = token.split(".", 1)
    if len(parts) != 2 or not parts[0] or not parts[1]:
        raise ValueError("invalid refresh token")
    try:
        token_id = UUID(parts[0])
    except ValueError as error:
        raise ValueError("invalid refresh token") from error
    return token_id, parts[1]


def verify_refresh_token_secret(secret: str, token_hash: str) -> bool:
    return compare_digest(hash_refresh_token_secret(secret), token_hash)


def is_refresh_token_active(
    refresh_token: RefreshToken,
    now: datetime | None = None,
) -> bool:
    current_time = now or datetime.now(UTC)
    if refresh_token.revoked_at is not None:
        return False
    expires_at = refresh_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    return expires_at > current_time


async def issue_refresh_token(
    session: AsyncSession,
    user: User,
    family_id: UUID | None = None,
) -> str:
    secret = token_urlsafe(32)
    refresh_token = RefreshToken(
        user_id=user.id,
        family_id=family_id or uuid4(),
        token_hash=hash_refresh_token_secret(secret),
        expires_at=datetime.now(UTC) + timedelta(days=settings.jwt_refresh_expires_days),
    )
    session.add(refresh_token)
    await session.flush()
    return build_refresh_token_value(refresh_token.id, secret)


async def get_valid_refresh_token(
    session: AsyncSession,
    token: str,
) -> tuple[RefreshToken, User]:
    try:
        token_id, secret = parse_refresh_token(token)
    except ValueError as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        ) from error
    refresh_token = await session.get(
        RefreshToken,
        token_id,
        with_for_update=True,
        populate_existing=True,
    )
    if refresh_token is None or not verify_refresh_token_secret(
        secret,
        refresh_token.token_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    if refresh_token.revoked_at is not None:
        await revoke_refresh_token_family(
            session,
            user_id=refresh_token.user_id,
            family_id=refresh_token.family_id,
        )
        await session.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    if not is_refresh_token_active(refresh_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    user = await session.get(User, refresh_token.user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    return refresh_token, user


async def revoke_refresh_token_family(
    session: AsyncSession,
    *,
    user_id: UUID,
    family_id: UUID,
) -> None:
    now = datetime.now(UTC)
    await session.execute(
        update(RefreshToken)
        .where(
            RefreshToken.user_id == user_id,
            RefreshToken.family_id == family_id,
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
    )


async def revoke_refresh_token(
    session: AsyncSession,
    refresh_token: RefreshToken,
) -> bool:
    now = datetime.now(UTC)
    result = await session.execute(
        update(RefreshToken)
        .where(
            RefreshToken.id == refresh_token.id,
            RefreshToken.revoked_at.is_(None),
        )
        .values(revoked_at=now)
        .returning(RefreshToken.id)
    )
    if result.scalar_one_or_none() is None:
        return False
    refresh_token.revoked_at = now
    return True


async def create_auth_response(
    session: AsyncSession,
    user: User,
    family_id: UUID | None = None,
) -> AuthResponse:
    refresh_token = await issue_refresh_token(session, user, family_id=family_id)
    await session.commit()
    return AuthResponse(
        access_token=create_access_token(
            user.id,
            user.email,
            user.email_verified,
        ),
        refresh_token=refresh_token,
        expires_in=settings.jwt_expires_minutes * 60,
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
    yield
    await engine.dispose()


app = FastAPI(title="FastAPI Postgres JWT Auth", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    try:
        async with engine.connect() as connection:
            await connection.execute(text("SELECT 1"))
    except SQLAlchemyError as error:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="database unavailable",
        ) from error
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
    return await create_auth_response(session, user)


@app.post("/auth/login", response_model=AuthResponse)
async def login(
    payload: LoginRequest,
    session: SessionDependency,
) -> AuthResponse:
    user = await session.scalar(select(User).where(User.email == str(payload.email)))
    if user is None:
        dummy = token_urlsafe(32)
        await run_in_threadpool(hash_password, dummy)
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

    return await create_auth_response(session, user)


@app.post("/auth/refresh", response_model=AuthResponse)
async def refresh(
    payload: RefreshRequest,
    session: SessionDependency,
) -> AuthResponse:
    refresh_token, user = await get_valid_refresh_token(
        session,
        payload.refresh_token,
    )
    if not await revoke_refresh_token(session, refresh_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    return await create_auth_response(
        session,
        user,
        family_id=refresh_token.family_id,
    )


@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    payload: RefreshRequest,
    session: SessionDependency,
) -> Response:
    refresh_token, _ = await get_valid_refresh_token(session, payload.refresh_token)
    if not await revoke_refresh_token(session, refresh_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
        )
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


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
        user.photo_url = str(payload.photo_url)

    await session.commit()
    await session.refresh(user)

    return UserResponse.model_validate(user)
