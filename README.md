# SupportAI Backend

FastAPI + PostgreSQL multi-tenant backend. Currently implemented: **Module 0** (foundation) and
**Module 1** (identity, tenancy, RBAC, audit log).

## Run it

```bash
cp .env.example .env            # then set SECRET_KEY
docker compose up -d            # Postgres (pgvector), Redis, MinIO
uv sync
uv run alembic upgrade head
uv run uvicorn app.main:app --reload   # docs at http://localhost:8000/docs
```

## Test it

Tests use a real Postgres and apply the real migrations:

```bash
TEST_DATABASE_URL=postgresql+psycopg://supportai:supportai@localhost:5433/supportai_test uv run pytest
uv run ruff check . && uv run mypy app
```
(create the `supportai_test` database first.)

## How a request flows

```
HTTP request
  -> RequestContextMiddleware      assigns request_id, logs the result
  -> Router (modules/*/router.py)  validates input (Pydantic), runs auth dependencies
  -> require_permission(...)       builds TenantContext(user, organization_id, role) from the JWT
                                   + a database membership check, then checks the permission
  -> Service (service.py)          business rules, audit entry, ONE commit
  -> Repository (repository.py)    SQL only; tenant repos always add WHERE organization_id = ...
  -> PostgreSQL
Errors: services raise AppError subclasses -> core/errors.py -> {"error": {code, message, request_id}}
```

## Where to look

| Concern | File |
|---|---|
| Config / env | `app/core/config.py` |
| Error format | `app/core/errors.py` |
| Passwords, JWT, refresh tokens | `app/core/security.py` |
| Tenant isolation | `app/db/tenant_repository.py`, `app/modules/auth/deps.py` |
| Roles & permissions | `app/modules/rbac/constants.py` |
| Tenant isolation tests | `tests/integration/test_tenant_isolation.py` |
