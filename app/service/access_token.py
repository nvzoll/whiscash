from datetime import UTC, datetime, timedelta
from typing import Literal
from uuid import UUID

import jwt
from pydantic import BaseModel, EmailStr, ValidationError

from app.core.config import settings


class TokenClaims(BaseModel):
    sub: UUID
    email: EmailStr
    email_verified: bool
    typ: Literal["access"]
    sid: UUID
    iat: int
    exp: int


def create_access_token(
    user_id: UUID,
    email: str,
    email_verified: bool,
    session_id: UUID,
    expires_minutes: int = settings.jwt_expires_minutes,
) -> str:
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "email": email,
        "email_verified": email_verified,
        "typ": "access",
        "sid": str(session_id),
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
                "require": [
                    "sub",
                    "email",
                    "email_verified",
                    "typ",
                    "sid",
                    "iat",
                    "exp",
                ],
            },
        )
        return TokenClaims.model_validate(payload)
    except (jwt.InvalidTokenError, ValidationError) as error:
        raise ValueError("invalid or expired access token") from error
