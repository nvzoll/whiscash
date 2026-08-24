FROM python:3.14-slim-bookworm AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1
ENV UV_LINK_MODE=copy
ENV UV_PYTHON_DOWNLOADS=0

RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev

COPY main.py models.py schemas.py settings.py alembic.ini entrypoint.sh /app/
COPY alembic /app/alembic

FROM python:3.14-slim-bookworm

RUN useradd --system --uid 1000 --create-home app

WORKDIR /app

COPY --from=builder --chown=app:app /app/.venv /app/.venv
COPY --from=builder --chown=app:app /app/main.py /app/models.py /app/schemas.py /app/settings.py /app/alembic.ini /app/entrypoint.sh /app/
COPY --from=builder --chown=app:app /app/alembic /app/alembic

RUN chmod +x /app/entrypoint.sh

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

USER app

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
