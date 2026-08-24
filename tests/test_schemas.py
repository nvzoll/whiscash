import pytest
from pydantic import ValidationError

from schemas import ProfileUpdate, SignupRequest, normalize_email


def test_normalize_email() -> None:
    assert normalize_email(" User@Example.COM ") == "user@example.com"


def test_signup_normalizes_profile_fields() -> None:
    signup = SignupRequest(
        email=" User@Example.COM ",
        password="correct-horse",
        display_name=" Ada Lovelace ",
    )

    assert str(signup.email) == "user@example.com"
    assert signup.display_name == "Ada Lovelace"


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
