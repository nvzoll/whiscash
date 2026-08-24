# Whiscash

FastAPI service for email/password auth with JWT access tokens, rotating refresh tokens, and PostgreSQL.

## Requirements

- [uv](https://docs.astral.sh/uv/)
- Docker Compose
- [mise](https://mise.jdx.dev/) (optional, for project tasks)

## Quick start

Put `JWT_SECRET` in a gitignored `.secrets.json` in the project root.
`mise run` loads that file into the task environment.

```sh
uv sync --group dev
mise run start
```

`mise run start` builds and starts the API on [http://localhost:8000](http://localhost:8000) and Postgres on `localhost:5432`. The API container runs `alembic upgrade head` before uvicorn.

OpenAPI docs: [http://localhost:8000/docs](http://localhost:8000/docs)

## Tasks

| Task | What it does |
| --- | --- |
| `mise run start` | `docker compose up --build -d --wait` |
| `mise run drop-db` | Drop the `auth` database |
| `mise run create-db` | Create the `auth` database |
| `mise run migrate` | `uv run alembic upgrade head` against localhost |
| `mise uvr` | `uv run` with env variables loaded |

Reset schema:

```sh
mise run start
mise run drop-db
mise run create-db
mise run migrate
```

`drop-db` and `create-db` use `docker compose exec` on the `postgres` service, so compose must already be up. `migrate` uses the local uv environment and `DATABASE_URL` (default `postgresql+asyncpg://auth:auth@localhost:5432/auth`).

Without mise:

```sh
docker compose up --build -d --wait
uv run alembic upgrade head
uv run alembic downgrade base
```

## Local API (no Docker API container)

Start Postgres only, migrate, then run uvicorn:

```sh
docker compose up -d --wait postgres
uv run alembic upgrade head
uv run uvicorn main:app --reload
```

## Configuration

Settings load from environment variables or a `.env` file.

| Variable | Default |
| --- | --- |
| `DATABASE_URL` | `postgresql+asyncpg://auth:auth@localhost:5432/auth` |
| `JWT_SECRET` | required; no default |
| `JWT_ALGORITHM` | `HS256` |
| `JWT_EXPIRES_MINUTES` | `60` |
| `JWT_REFRESH_EXPIRES_DAYS` | `30` |


## API

| Method | Path | Auth |
| --- | --- | --- |
| `GET` | `/health` | no |
| `POST` | `/auth/signup` | no |
| `POST` | `/auth/login` | no |
| `POST` | `/auth/refresh` | refresh token body |
| `POST` | `/auth/logout` | refresh token body |
| `GET` | `/auth/me` | Bearer access token |
| `PATCH` | `/auth/me` | Bearer access token |

Signup and login return `access_token`, `refresh_token`, `expires_in`, and `user`. Send the access token as `Authorization: Bearer <token>`. Refresh rotates the refresh token; logout revokes it.

Passwords must be at least 8 characters and at most 72 UTF-8 bytes. Emails are stored lowercased.

## Schema

ORM models in `models.py` are the source of truth. The initial Alembic revision snapshots `user` and `refresh_token`.

After changing models:

```sh
uv run alembic revision --autogenerate -m "describe the change"
```

Review the generated file, then `mise run migrate` or `uv run alembic upgrade head`.

## Tests

```sh
uv run pytest
```

API tests use an in-memory mock session and do not need Postgres.
