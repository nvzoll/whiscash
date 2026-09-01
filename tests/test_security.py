from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest

from app.core.config import settings
from app.service.access_token import AccessTokenService
from app.service.password import PasswordService


def test_password_hash_and_verify() -> None:
    password_hash = PasswordService.hash("correct-horse")

    assert password_hash != "correct-horse"
    assert PasswordService.verify("correct-horse", password_hash)
    assert not PasswordService.verify("wrong-password", password_hash)
    assert not PasswordService.verify("correct-horse", "not-a-bcrypt-hash")


def test_access_token_round_trip() -> None:
    user_id = uuid4()
    session_id = uuid4()
    token = AccessTokenService.create(
        user_id,
        "user@example.com",
        email_verified=True,
        session_id=session_id,
        expires_minutes=5,
    )

    claims = AccessTokenService.decode(token)

    assert claims.sub == user_id
    assert str(claims.email) == "user@example.com"
    assert claims.email_verified is True
    assert claims.typ == "access"
    assert claims.sid == session_id
    assert claims.exp > claims.iat


def test_expired_access_token_is_rejected() -> None:
    token = AccessTokenService.create(
        uuid4(),
        "user@example.com",
        email_verified=False,
        session_id=uuid4(),
        expires_minutes=-1,
    )

    with pytest.raises(ValueError, match="invalid or expired access token"):
        AccessTokenService.decode(token)


def test_invalid_access_token_is_rejected() -> None:
    with pytest.raises(ValueError, match="invalid or expired access token"):
        AccessTokenService.decode("not-a-token")


def _token_payload(**overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "sub": str(uuid4()),
        "email": "user@example.com",
        "email_verified": False,
        "typ": "access",
        "sid": str(uuid4()),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }
    payload.update(overrides)
    return payload


def _encode_token(**overrides: object) -> str:
    return jwt.encode(
        _token_payload(**overrides),
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )


def test_refresh_typ_token_is_rejected_as_access_token() -> None:
    token = _encode_token(typ="refresh")

    with pytest.raises(ValueError, match="invalid or expired access token"):
        AccessTokenService.decode(token)


def test_access_token_without_typ_is_rejected() -> None:
    payload = _token_payload()
    del payload["typ"]
    token = jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(ValueError, match="invalid or expired access token"):
        AccessTokenService.decode(token)


def test_access_token_without_sid_is_rejected() -> None:
    payload = _token_payload()
    del payload["sid"]
    token = jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(ValueError, match="invalid or expired access token"):
        AccessTokenService.decode(token)
