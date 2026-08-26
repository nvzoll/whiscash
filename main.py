from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from secrets import token_urlsafe
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Response, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from auth.access_token import create_access_token, decode_access_token
from auth.password import hash_password, verify_password
from auth.refresh_token import (
    get_active_session_token,
    get_valid_refresh_token,
    invalid_refresh_token,
    issue_refresh_token,
    revoke_refresh_token,
)
from db import SessionDependency, engine
from models import RefreshToken, User
from schemas import (
    AuthResponse,
    LoginRequest,
    ProfileUpdate,
    RefreshRequest,
    SignupRequest,
    UserResponse,
)
from settings import settings

bearer_scheme = HTTPBearer(auto_error=False)

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

    if (user := await session.get(User, claims.sub)) is None:
        raise unauthorized

    if await get_active_session_token(session, claims.sid) is None:
        raise unauthorized

    return user


CurrentUserDependency = Annotated[User, Depends(get_current_user)]


async def create_auth_response(session: AsyncSession, user: User) -> AuthResponse:
    session_id, refresh_token = await issue_refresh_token(session, user)
    await session.commit()

    return AuthResponse(
        access_token=create_access_token(user.id, user.email, user.email_verified, session_id),
        refresh_token=refresh_token,
        expires_in=settings.jwt_expires_minutes * 60,
        user=UserResponse.model_validate(user),
    )


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
    if (user := await session.scalar(select(User).where(User.email == str(payload.email)))) is None:
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
    refresh_token, user = await get_valid_refresh_token(session, payload.refresh_token)

    rotated_id, rotated = await issue_refresh_token(session, user)

    if not await revoke_refresh_token(session, refresh_token):
        if (
            unused := await session.get(
                RefreshToken,
                rotated_id,
                populate_existing=True,
            )
        ) is not None:
            await revoke_refresh_token(session, unused)
        await session.commit()

        raise invalid_refresh_token()

    await session.commit()

    return AuthResponse(
        access_token=create_access_token(user.id, user.email, user.email_verified, rotated_id),
        refresh_token=rotated,
        expires_in=settings.jwt_expires_minutes * 60,
        user=UserResponse.model_validate(user),
    )


@app.post("/auth/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    payload: RefreshRequest,
    session: SessionDependency,
) -> Response:
    refresh_token, _ = await get_valid_refresh_token(session, payload.refresh_token)
    if not await revoke_refresh_token(session, refresh_token):
        raise invalid_refresh_token()
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
    if payload.display_name is not None:
        user.display_name = payload.display_name

    if payload.photo_url is not None:
        user.photo_url = str(payload.photo_url)

    await session.commit()
    await session.refresh(user)

    return UserResponse.model_validate(user)
