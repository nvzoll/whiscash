from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, status
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.core.router import router
from app.db.session import engine
from app.middleware.trace_id import TraceIdMiddleware


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    yield
    await engine.dispose()


def new_app() -> FastAPI:
    app = FastAPI(title="Auth Service", lifespan=lifespan)
    app.add_middleware(TraceIdMiddleware)
    app.include_router(router)

    @app.get("/health")
    async def health() -> dict[str, str]:
        try:
            async with engine.connect() as connection:
                await connection.execute(text("SELECT 1"))
        except SQLAlchemyError as error:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Database unavailable",
            ) from error
        return {"status": "ok"}

    return app


app = new_app()
