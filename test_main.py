from uuid import uuid4

import pytest
from pydantic import ValidationError

from main import (
    ProfileUpdate,
    SignupRequest,
    create_access_token,
    decode_access_token,
    hash_password,
    normalize_email,
    verify_password,
)


def test_normalize_email() -> None:
    assert normalize_email(" User@Example.COM ") == "user@example.com"


def test_signup_normalizes_profile_fields() -> None:
    signup = SignupRequest(
        email=" User@Example.COM ",
        password="correct-horse",
        display_name=" Ada Lovelace ",
        photo_url="https://example.com/avatar.png",
    )

    assert str(signup.email) == "user@example.com"
    assert signup.display_name == "Ada Lovelace"
    assert str(signup.photo_url) == "https://example.com/avatar.png"


@pytest.mark.parametrize(
    "password",
    [
        "short",
        "é" * 37,
    ],
)
def test_signup_rejects_password_outside_bcrypt_limits(password: str) -> None:
    with pytest.raises(ValidationError):
        SignupRequest(email="user@example.com", password=password)


def test_signup_accepts_72_byte_password() -> None:
    signup = SignupRequest(
        email="user@example.com",
        password="é" * 36,
    )

    assert signup.password == "é" * 36


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


def test_profile_update_distinguishes_omitted_and_null_fields() -> None:
    omitted = ProfileUpdate(display_name=" New Name ")
    cleared = ProfileUpdate(photo_url=None)

    assert omitted.display_name == "New Name"
    assert omitted.model_fields_set == {"display_name"}
    assert cleared.photo_url is None
    assert cleared.model_fields_set == {"photo_url"}


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("display_name", "   "),
        ("display_name", "x" * 129),
        ("photo_url", "ftp://example.com/avatar.png"),
        ("photo_url", "https://example.com/" + "x" * 2048),
    ],
)
def test_profile_update_rejects_invalid_values(field: str, value: str) -> None:
    with pytest.raises(ValidationError):
        ProfileUpdate.model_validate({field: value})


def test_request_models_forbid_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        SignupRequest.model_validate(
            {
                "email": "user@example.com",
                "password": "correct-horse",
                "email_verified": True,
            }
        )
