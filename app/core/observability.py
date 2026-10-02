import logfire
from fastapi import FastAPI

from app.core.config import settings
from app.db.session import engine


def configure_logfire(app: FastAPI) -> None:
    token = settings.logfire_token.get_secret_value() if settings.logfire_token else None
    logfire.configure(
        service_name="whiscash-api",
        token=token,
        send_to_logfire="if-token-present",
        console=False,
        scrubbing=logfire.ScrubbingOptions(extra_patterns=["token"]),
    )

    logfire.instrument_fastapi(app, excluded_urls="/health")
    logfire.instrument_sqlalchemy(engine=engine)
    logfire.instrument_redis()
