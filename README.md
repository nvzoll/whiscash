# Whiscash

Service for first-party, non-delegated dual-token authentication (JWT + refresh token). Inspiration: Auth0, Clerk, Firebase Auth.

FastAPI + Postgres + Redis.

## Requirements

- [uv](https://docs.astral.sh/uv/)
- Docker Compose
- [mise](https://mise.jdx.dev/) (optional, for project tasks)

## Quick start

Do `mise run gen-secrets` to generate a random `JWT_SECRET` in a gitignored `.secrets.json` in the project root.

`mise run` loads that file into the task environment with non-secret env vars from mise.toml.

You can also encrypt that file with `sops` and mise will [decrypt](https://mise.jdx.dev/environments/secrets/sops.html) it on every `mise run`.

```sh
uv sync --group dev
mise run gen-secrets
mise run start
```

`mise run start` builds and starts the API on [http://localhost:8000](http://localhost:8000), a refresh-token purge sidecar, Postgres on `localhost:5432`, and Redis on `localhost:6379`. The API container runs `alembic upgrade head` before uvicorn.

OpenAPI docs: [http://localhost:8000/docs](http://localhost:8000/docs)

## Tasks

| Task | What it does |
| --- | --- |
| `mise run start` | `docker compose up --build -d --wait` |
| `mise run drop-db` | Drop the `auth` database |
| `mise run create-db` | Create the `auth` database |
| `mise run migrate` | `uv run alembic upgrade head` against localhost |
| `mise uvr` | `uv run` with env variables loaded |
| `mise run gen-secrets` | Generate .secrets.json |
| `mise run create-service-key -- <name>` | Issue a new service-client API key (prints once) |
| `mise run revoke-service-key -- <name>` | Revoke that service's active API key |
| `mise run list-service-keys` | List service-client API keys and their status |

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

Start Postgres and Redis, migrate, then run uvicorn:

```sh
docker compose up -d --wait postgres redis
uv run alembic upgrade head
uv run uvicorn app.core.main:app --reload
```

## Configuration

Settings load from environment variables and `.secrets.json` file.

| Variable | Default |
| --- | --- |
| `DATABASE_URL` | `postgresql+asyncpg://auth:auth@localhost:5432/auth` |
| `REDIS_URL` | required; no default |
| `JWT_SECRET` | required; no default |
| `JWT_ALGORITHM` | `HS256` |
| `JWT_EXPIRES_MINUTES` | `60` |
| `JWT_REFRESH_EXPIRES_DAYS` | `30` |
| `JWT_REFRESH_REUSE_GRACE_SECONDS` | `2` |
| `PASSWORD_RESET_TOKEN_EXPIRES_MINUTES` | `30` |
| `LOGFIRE_TOKEN` | optional; traces are sent to Logfire only when set |
| `LOGFIRE_ENVIRONMENT` | optional; Logfire environment tag |

Every response carries an `x-trace-id` header with the OpenTelemetry trace id, the same one Logfire shows. Send a W3C `traceparent` header to continue an existing trace.


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
| `POST` | `/auth/password-reset/request` | `X-Service-Key` |
| `POST` | `/auth/password-reset/confirm` | no |

Signup and login return `access_token`, `refresh_token`, `expires_in`, and `user`. Send the access token as `Authorization: Bearer <token>`. Refresh rotates the refresh token and issues a new access token; the previous access token is invalidated. Logout revokes the refresh token, which also invalidates its access token immediately.

Passwords must be at least 8 characters and at most 72 UTF-8 bytes. Emails are stored lowercased.

Whiscash does not send email itself. `/auth/password-reset/request` (callable only by a trusted consumer service, see "Service clients" below) mints a short-lived, single-use reset token and returns it for the caller to embed in an email it sends itself; if the email doesn't match a user, the response still succeeds but omits the token. `/auth/password-reset/confirm` is public and consumes that token: it sets the new password, marks the account's email as verified (completing an email-based reset proves inbox ownership), and revokes every one of the user's refresh-token sessions across all devices.

## Service clients

Some endpoints (currently `/auth/password-reset/request`) are only callable by a trusted backend consumer, authenticated via an `X-Service-Key` header checked against the `service_client` table. Keys are issued directly against the database, not over HTTP:

```sh
mise run create-service-key -- <name>
```

This prints the raw key once — it is not recoverable afterwards, only its hash is stored.

To pull a key, revoke it by name:

```sh
mise run revoke-service-key -- <name>
mise run list-service-keys
```

Revocation takes effect immediately: `/auth/password-reset/request` rejects a revoked key with `401 invalid_service_key`.

A name is unique among *live* keys only, so rotation is revoke-then-re-mint under the same name. The revoked row keeps its name as a record of what was issued; only one key per name is ever active.

## Schema

ORM models in `app/db/models.py` are the source of truth. The initial Alembic revision snapshots `user` and `refresh_token`; a later revision adds `password_reset_token` and `service_client`.

After changing models:

```sh
uv run alembic revision --autogenerate -m "describe the change"
```

Review the generated file, then `mise run migrate` or `uv run alembic upgrade head`.

## Tests

```sh
uv run pytest # Against mocked repo objects
uv run pytest --db-backend=postgres # Against one-shot postgres and redis containers
```

Default API tests use mocked repository objects and do not need Postgres.

The purge sidecar (`sidecar/`) is a separate uv project with its own dependencies and tests:

```sh
cd sidecar
uv run pytest
```

Sidecar tests require Docker and run against a PostgreSQL container with the root Alembic migrations.

