from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
import pytest

from main import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)
from settings import settings


def test_password_hash_and_verify() -> None:
    password_hash = hash_password("correct-horse")

    assert password_hash != "correct-horse"
    assert verify_password("correct-horse", password_hash)
    assert not verify_password("wrong-password", password_hash)
    assert not verify_password("correct-horse", "not-a-bcrypt-hash")


def test_access_token_round_trip() -> None:
    user_id = uuid4()
    token = create_access_token(
        user_id,
        "user@example.com",
        email_verified=True,
        expires_minutes=5,
    )

    claims = decode_access_token(token)

    assert claims.sub == user_id
    assert str(claims.email) == "user@example.com"
    assert claims.email_verified is True
    assert claims.typ == "access"
    assert claims.exp > claims.iat


def test_expired_access_token_is_rejected() -> None:
    token = create_access_token(
        uuid4(),
        "user@example.com",
        email_verified=False,
        expires_minutes=-1,
    )

    with pytest.raises(ValueError, match="invalid or expired access token"):
        decode_access_token(token)


def test_invalid_access_token_is_rejected() -> None:
    with pytest.raises(ValueError, match="invalid or expired access token"):
        decode_access_token("not-a-token")


def _token_payload(**overrides: object) -> dict[str, object]:
    now = datetime.now(UTC)
    payload: dict[str, object] = {
        "sub": str(uuid4()),
        "email": "user@example.com",
        "email_verified": False,
        "typ": "access",
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
        decode_access_token(token)


def test_access_token_without_typ_is_rejected() -> None:
    payload = _token_payload()
    del payload["typ"]
    token = jwt.encode(
        payload,
        settings.jwt_secret,
        algorithm=settings.jwt_algorithm,
    )

    with pytest.raises(ValueError, match="invalid or expired access token"):
        decode_access_token(token)
