from fastapi import APIRouter, Response, status

from app.controller.deps import AuthControllerDependency, CurrentServiceClientDependency, CurrentUserDependency
from app.controller.validations import (
    AuthResponse,
    LoginRequest,
    PasswordResetConfirm,
    PasswordResetIssued,
    PasswordResetRequest,
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


@router.post("/password-reset/request", response_model=PasswordResetIssued)
async def request_password_reset(
    payload: PasswordResetRequest,
    controller: AuthControllerDependency,
    _service_client: CurrentServiceClientDependency,
) -> PasswordResetIssued:
    return await controller.request_password_reset(payload)


@router.post("/password-reset/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm_password_reset(
    payload: PasswordResetConfirm,
    controller: AuthControllerDependency,
) -> Response:
    await controller.confirm_password_reset(payload)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
