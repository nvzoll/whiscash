from typing import Literal, NamedTuple

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Limits(NamedTuple):
    min: int
    max: int


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", frozen=True)

    database_url: str
    jwt_secret: str
    redis_url: str
    jwt_algorithm: Literal["HS256"] = "HS256"
    jwt_expires_minutes: int = Field(default=60, gt=0)
    jwt_refresh_expires_days: int = Field(default=30, gt=0)
    jwt_refresh_reuse_grace_seconds: int = Field(default=2, ge=0)
    password_reset_token_expires_minutes: int = Field(default=30, gt=0)

    password_limits: Limits = Limits(min=8, max=72)


settings = Settings()


if __name__ == "__main__":
    print(settings.model_dump_json(indent=4))
