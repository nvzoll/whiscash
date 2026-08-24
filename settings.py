from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", frozen=True)

    database_url: str = "postgresql+asyncpg://auth:auth@localhost:5432/auth"
    jwt_secret: str = "development-only-change-me-32-bytes"
    jwt_algorithm: str = "HS256"
    jwt_expires_minutes: int = Field(default=60, gt=0)
    jwt_refresh_expires_days: int = Field(default=30, gt=0)


settings = Settings()
