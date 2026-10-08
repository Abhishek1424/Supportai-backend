"""Shared test fixtures.

Tests run against a REAL PostgreSQL (set TEST_DATABASE_URL), created via the
actual Alembic migrations. That way migrations, constraints and JSONB behave
exactly as in production; SQLite would hide real bugs.
"""

import os
from collections.abc import Iterator
from dataclasses import dataclass

# Settings must be in the environment BEFORE app modules are imported.
os.environ["APP_ENV"] = "test"
os.environ["DATABASE_URL"] = os.environ.get(
    "TEST_DATABASE_URL", "postgresql+psycopg://supportai:supportai@localhost:5432/supportai_test"
)
os.environ["SECRET_KEY"] = "test-secret-key-test-secret-key-test-secret"
os.environ.pop("REDIS_URL", None)
os.environ["AUTH_RATE_LIMIT_ATTEMPTS"] = "1000"  # high by default; the rate-limit test lowers it

import pytest  # noqa: E402
from alembic.config import Config  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from sqlalchemy import text  # noqa: E402

from alembic import command  # noqa: E402
from app.core.rate_limit import InMemoryRateLimiter, get_rate_limiter  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import get_engine  # noqa: E402
from app.main import create_app  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _migrated_database() -> None:
    """Rebuild the schema once per test run by applying every Alembic migration."""
    with get_engine().begin() as conn:
        conn.execute(text("DROP SCHEMA public CASCADE"))
        conn.execute(text("CREATE SCHEMA public"))
    command.upgrade(Config("alembic.ini"), "head")


@pytest.fixture(autouse=True)
def _clean_tables() -> Iterator[None]:
    """Empty every table after each test so tests cannot affect each other."""
    yield
    tables = ", ".join(t.name for t in Base.metadata.sorted_tables)
    with get_engine().begin() as conn:
        conn.execute(text(f"TRUNCATE {tables} CASCADE"))


@pytest.fixture
def client() -> Iterator[TestClient]:
    """HTTP client against the full app, with an isolated in-memory rate limiter."""
    app = create_app()
    limiter = InMemoryRateLimiter()
    app.dependency_overrides[get_rate_limiter] = lambda: limiter
    with TestClient(app) as test_client:
        yield test_client


@dataclass
class Account:
    """A registered user plus the credentials tests need."""

    email: str
    password: str
    access_token: str
    refresh_token: str

    @property
    def headers(self) -> dict[str, str]:
        """Authorization header for this account."""
        return {"Authorization": f"Bearer {self.access_token}"}


DEFAULT_PASSWORD = "correct-horse-battery"


def register_account(
    client: TestClient, email: str = "owner@abc.com", org_name: str = "ABC Insurance"
) -> Account:
    """Register a new organization+owner through the real API and return its credentials."""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": DEFAULT_PASSWORD,
            "full_name": "Test Owner",
            "organization_name": org_name,
        },
    )
    assert response.status_code == 201, response.text
    body = response.json()
    return Account(email, DEFAULT_PASSWORD, body["access_token"], body["refresh_token"])


def add_member(
    client: TestClient, owner: Account, email: str, role: str, password: str = DEFAULT_PASSWORD
) -> Account:
    """Add a member to the owner's org via the API, then log them in; return their Account."""
    response = client.post(
        "/api/v1/organizations/current/members",
        headers=owner.headers,
        json={"email": email, "role": role, "full_name": "Member", "password": password},
    )
    assert response.status_code == 201, response.text
    login = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200, login.text
    body = login.json()
    return Account(email, password, body["access_token"], body["refresh_token"])
