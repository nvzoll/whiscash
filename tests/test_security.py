from uuid import uuid4

import pytest

from main import (
    create_access_token,
    decode_access_token,
    hash_password,
    verify_password,
)


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
