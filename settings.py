from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore", frozen=True)

    database_url: str
    jwt_secret: str
    jwt_algorithm: str = "HS256"
    jwt_expires_minutes: int = Field(default=60, gt=0)
    jwt_refresh_expires_days: int = Field(default=30, gt=0)


settings = Settings()


if __name__ == "__main__":
    print(settings.model_dump_json(indent=4))
