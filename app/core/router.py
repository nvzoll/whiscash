from fastapi import APIRouter, Response, status

from app.controller.deps import AuthControllerDependency, CurrentUserDependency
from app.controller.validations import (
    AuthResponse,
    LoginRequest,
    ProfileUpdate,
    RefreshRequest,
    SignupRequest,
    UserResponse,
)

router = APIRouter(prefix="/auth")


@router.post(
    "/signup",
    response_model=AuthResponse,
    status_code=status.HTTP_201_CREATED,
)
async def signup(
    payload: SignupRequest,
    controller: AuthControllerDependency,
) -> AuthResponse:
    return await controller.signup(payload)


@router.post("/login", response_model=AuthResponse)
async def login(
    payload: LoginRequest,
    controller: AuthControllerDependency,
) -> AuthResponse:
    return await controller.login(payload)


@router.post("/refresh", response_model=AuthResponse)
async def refresh(
    payload: RefreshRequest,
    controller: AuthControllerDependency,
) -> AuthResponse:
    return await controller.refresh(payload)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    payload: RefreshRequest,
    controller: AuthControllerDependency,
) -> Response:
    await controller.logout(payload)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=UserResponse)
async def get_self(
    user: CurrentUserDependency,
    controller: AuthControllerDependency,
) -> UserResponse:
    return await controller.get_self(user)


@router.patch("/me", response_model=UserResponse)
async def update_self(
    payload: ProfileUpdate,
    user: CurrentUserDependency,
    controller: AuthControllerDependency,
) -> UserResponse:
    return await controller.update_self(payload, user)
