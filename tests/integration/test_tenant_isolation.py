"""Tenant isolation: Client A must never see or touch Client B's data.

These are the most important tests in the project. Every new tenant-owned
endpoint added later should get a matching case here.
"""

from fastapi.testclient import TestClient

from tests.conftest import add_member, register_account

MEMBERS = "/api/v1/organizations/current/members"


def _two_tenants(client: TestClient):  # type: ignore[no-untyped-def]
    org_a = register_account(client, "owner@a.com", "Company A")
    org_b = register_account(client, "owner@b.com", "Company B")
    add_member(client, org_a, "agent@a.com", "agent")
    add_member(client, org_b, "agent@b.com", "agent")
    return org_a, org_b


def test_member_lists_only_contain_own_tenant(client: TestClient) -> None:
    org_a, org_b = _two_tenants(client)
    emails_a = {m["email"] for m in client.get(MEMBERS, headers=org_a.headers).json()["items"]}
    emails_b = {m["email"] for m in client.get(MEMBERS, headers=org_b.headers).json()["items"]}
    assert emails_a == {"owner@a.com", "agent@a.com"}
    assert emails_b == {"owner@b.com", "agent@b.com"}


def test_search_cannot_reach_other_tenants_members(client: TestClient) -> None:
    org_a, _ = _two_tenants(client)
    result = client.get(MEMBERS, params={"q": "@b.com"}, headers=org_a.headers).json()
    assert result["total"] == 0


def test_cannot_modify_or_delete_another_tenants_member(client: TestClient) -> None:
    org_a, org_b = _two_tenants(client)
    victim_id = next(
        m["id"]
        for m in client.get(MEMBERS, headers=org_b.headers).json()["items"]
        if m["email"] == "agent@b.com"
    )

    patch = client.patch(f"{MEMBERS}/{victim_id}", headers=org_a.headers, json={"role": "viewer"})
    delete = client.delete(f"{MEMBERS}/{victim_id}", headers=org_a.headers)
    # 404 (not 403) so Company A cannot even confirm that the id exists.
    assert patch.status_code == 404 and patch.json()["error"]["code"] == "MEMBER_NOT_FOUND"
    assert delete.status_code == 404

    still_there = client.get(MEMBERS, headers=org_b.headers).json()["total"]
    assert still_there == 2


def test_audit_logs_are_tenant_scoped(client: TestClient) -> None:
    org_a, org_b = _two_tenants(client)
    client.patch(
        "/api/v1/organizations/current", headers=org_b.headers, json={"name": "B Secret Rename"}
    )

    logs_a = client.get("/api/v1/audit-logs", headers=org_a.headers).json()
    assert "B Secret Rename" not in str(logs_a)
    assert all(e["actor_user_id"] is not None for e in logs_a["items"])
    assert (
        client.get(
            "/api/v1/audit-logs", params={"action": "organization.updated"}, headers=org_a.headers
        ).json()["total"]
        == 0
    )


def test_organization_endpoint_returns_callers_org_only(client: TestClient) -> None:
    org_a, org_b = _two_tenants(client)
    assert (
        client.get("/api/v1/organizations/current", headers=org_a.headers).json()["name"]
        == "Company A"
    )
    assert (
        client.get("/api/v1/organizations/current", headers=org_b.headers).json()["name"]
        == "Company B"
    )


def test_token_cannot_be_used_for_an_org_the_user_is_not_in(client: TestClient) -> None:
    """A user from A cannot log in to B by passing B's organization_id."""
    org_a, org_b = _two_tenants(client)
    b_id = client.get("/api/v1/organizations/current", headers=org_b.headers).json()["id"]
    response = client.post(
        "/api/v1/auth/login",
        json={"email": org_a.email, "password": org_a.password, "organization_id": b_id},
    )
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "NO_ACTIVE_ORGANIZATION"


def test_user_in_two_orgs_gets_org_scoped_tokens(client: TestClient) -> None:
    """One person, two workspaces: each token only exposes its own workspace."""
    org_a, org_b = _two_tenants(client)
    # owner@a.com is also added to Company B as a viewer.
    added = client.post(
        MEMBERS, headers=org_b.headers, json={"email": "owner@a.com", "role": "viewer"}
    )
    assert added.status_code == 201

    b_id = client.get("/api/v1/organizations/current", headers=org_b.headers).json()["id"]
    login_b = client.post(
        "/api/v1/auth/login",
        json={"email": "owner@a.com", "password": org_a.password, "organization_id": b_id},
    ).json()
    as_b = {"Authorization": f"Bearer {login_b['access_token']}"}

    me = client.get("/api/v1/auth/me", headers=as_b).json()
    assert me["organization"]["name"] == "Company B"
    assert me["role"] == "viewer"  # role differs per org
    assert client.get("/api/v1/audit-logs", headers=as_b).status_code == 403
    # Their original token still acts as owner of Company A.
    assert client.get("/api/v1/auth/me", headers=org_a.headers).json()["role"] == "owner"
