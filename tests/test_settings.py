import pytest
from pydantic import ValidationError

from settings import Settings


def test_settings_reads_environment_variables(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://user:pass@db:5432/app")
    monkeypatch.setenv("JWT_SECRET", "unit-test-secret-change-me-32-bytes")
    monkeypatch.setenv("JWT_ALGORITHM", "HS512")
    monkeypatch.setenv("JWT_EXPIRES_MINUTES", "15")

    loaded = Settings()

    assert loaded.database_url == "postgresql+asyncpg://user:pass@db:5432/app"
    assert loaded.jwt_secret == "unit-test-secret-change-me-32-bytes"
    assert loaded.jwt_algorithm == "HS512"
    assert loaded.jwt_expires_minutes == 15


@pytest.mark.parametrize("expires_minutes", [0, -1])
def test_settings_rejects_non_positive_jwt_expiry(expires_minutes: int) -> None:
    with pytest.raises(ValidationError):
        Settings(jwt_expires_minutes=expires_minutes)


def test_settings_reads_refresh_expiry(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("JWT_REFRESH_EXPIRES_DAYS", "7")

    loaded = Settings()

    assert loaded.jwt_refresh_expires_days == 7


@pytest.mark.parametrize("expires_days", [0, -1])
def test_settings_rejects_non_positive_refresh_expiry(expires_days: int) -> None:
    with pytest.raises(ValidationError):
        Settings(jwt_refresh_expires_days=expires_days)
