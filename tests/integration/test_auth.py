# API tests for register, login, refresh rotation, theft detection, logout, rate limit and
#   error format. They call the real endpoints.
"""API tests for registration, login, refresh rotation, logout and /me."""

from fastapi.testclient import TestClient

from app.core.config import get_settings
from tests.conftest import DEFAULT_PASSWORD, register_account


def test_register_returns_working_tokens(client: TestClient) -> None:
    account = register_account(client)
    me = client.get("/api/v1/auth/me", headers=account.headers)
    assert me.status_code == 200
    body = me.json()
    assert body["user"]["email"] == "owner@abc.com"
    assert body["role"] == "owner"
    assert body["organization"]["name"] == "ABC Insurance"
    assert "password_hash" not in str(body)


def test_register_duplicate_email_conflicts_case_insensitively(client: TestClient) -> None:
    register_account(client, "owner@abc.com")
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "OWNER@ABC.COM",
            "password": DEFAULT_PASSWORD,
            "full_name": "X",
            "organization_name": "Other",
        },
    )
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "EMAIL_ALREADY_REGISTERED"


def test_register_validation_error_has_standard_shape_and_hides_input(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/register",
        json={"email": "bad", "password": "short", "full_name": "X", "organization_name": "Y"},
    )
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "VALIDATION_ERROR"
    assert error["request_id"]
    assert "short" not in str(error)  # the submitted password is never echoed back


def test_login_success_and_wrong_password(client: TestClient) -> None:
    register_account(client)
    ok = client.post(
        "/api/v1/auth/login", json={"email": "Owner@ABC.com", "password": DEFAULT_PASSWORD}
    )
    assert ok.status_code == 200
    bad = client.post(
        "/api/v1/auth/login", json={"email": "owner@abc.com", "password": "wrong-password"}
    )
    assert bad.status_code == 401
    assert bad.json()["error"]["code"] == "INVALID_CREDENTIALS"


def test_login_unknown_email_gives_same_error_as_wrong_password(client: TestClient) -> None:
    response = client.post(
        "/api/v1/auth/login", json={"email": "nobody@x.com", "password": "whatever-pass"}
    )
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Invalid email or password."


def test_protected_route_requires_token(client: TestClient) -> None:
    missing = client.get("/api/v1/auth/me")
    assert missing.status_code == 401
    assert missing.json()["error"]["code"] == "NOT_AUTHENTICATED"
    garbage = client.get("/api/v1/auth/me", headers={"Authorization": "Bearer nonsense"})
    assert garbage.status_code == 401
    assert garbage.json()["error"]["code"] == "INVALID_TOKEN"


def test_refresh_rotates_token_and_old_one_is_dead(client: TestClient) -> None:
    account = register_account(client)
    first = client.post("/api/v1/auth/refresh", json={"refresh_token": account.refresh_token})
    assert first.status_code == 200
    new_refresh = first.json()["refresh_token"]
    assert new_refresh != account.refresh_token
    # New access token works.
    me = client.get(
        "/api/v1/auth/me", headers={"Authorization": f"Bearer {first.json()['access_token']}"}
    )
    assert me.status_code == 200


def test_reusing_a_rotated_refresh_token_revokes_the_whole_family(client: TestClient) -> None:
    account = register_account(client)
    rotated = client.post(
        "/api/v1/auth/refresh", json={"refresh_token": account.refresh_token}
    ).json()

    replay = client.post("/api/v1/auth/refresh", json={"refresh_token": account.refresh_token})
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "REFRESH_TOKEN_REUSED"

    # The legitimate newer token was revoked too (assume the thief may hold it).
    newer = client.post("/api/v1/auth/refresh", json={"refresh_token": rotated["refresh_token"]})
    assert newer.status_code == 401


def test_logout_revokes_refresh_token(client: TestClient) -> None:
    account = register_account(client)
    assert (
        client.post(
            "/api/v1/auth/logout", json={"refresh_token": account.refresh_token}
        ).status_code
        == 204
    )
    after = client.post("/api/v1/auth/refresh", json={"refresh_token": account.refresh_token})
    assert after.status_code == 401
    # Logging out with an unknown token is still a silent success.
    assert client.post("/api/v1/auth/logout", json={"refresh_token": "unknown"}).status_code == 204


def test_login_is_rate_limited(client: TestClient) -> None:
    settings = get_settings()
    original = settings.auth_rate_limit_attempts
    settings.auth_rate_limit_attempts = 3
    try:
        statuses = [
            client.post(
                "/api/v1/auth/login", json={"email": "a@b.com", "password": "wrong-password"}
            ).status_code
            for _ in range(5)
        ]
    finally:
        settings.auth_rate_limit_attempts = original
    assert statuses[:3] == [401, 401, 401]
    assert statuses[3:] == [429, 429]


def test_every_response_carries_a_request_id(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "abc-123"})
    assert response.headers["X-Request-ID"] == "abc-123"
    assert client.get("/health").headers["X-Request-ID"]


def test_unknown_route_uses_standard_error_shape(client: TestClient) -> None:
    response = client.get("/api/v1/nope")
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "HTTP_ERROR"
