"""API tests for organization/member management, RBAC and the audit log."""

from fastapi.testclient import TestClient

from tests.conftest import add_member, register_account

MEMBERS = "/api/v1/organizations/current/members"


def test_owner_can_list_search_and_sort_members(client: TestClient) -> None:
    owner = register_account(client)
    add_member(client, owner, "zed@abc.com", "agent")
    add_member(client, owner, "amy@abc.com", "viewer")

    listing = client.get(MEMBERS, headers=owner.headers).json()
    assert listing["total"] == 3

    searched = client.get(MEMBERS, params={"q": "amy"}, headers=owner.headers).json()
    assert [m["email"] for m in searched["items"]] == ["amy@abc.com"]

    ordered = client.get(
        MEMBERS, params={"sort_by": "email", "sort_order": "desc"}, headers=owner.headers
    ).json()
    emails = [m["email"] for m in ordered["items"]]
    assert emails == sorted(emails, reverse=True)

    paged = client.get(MEMBERS, params={"page": 2, "page_size": 2}, headers=owner.headers).json()
    assert len(paged["items"]) == 1 and paged["total"] == 3


def test_invalid_sort_key_is_rejected_not_injected(client: TestClient) -> None:
    owner = register_account(client)
    response = client.get(
        MEMBERS, params={"sort_by": "password_hash; DROP TABLE users"}, headers=owner.headers
    )
    assert response.status_code == 422


def test_member_list_never_exposes_password_hashes(client: TestClient) -> None:
    owner = register_account(client)
    assert "password" not in client.get(MEMBERS, headers=owner.headers).text


def test_agent_can_read_members_but_not_manage_or_read_audit(client: TestClient) -> None:
    owner = register_account(client)
    agent = add_member(client, owner, "agent@abc.com", "agent")

    assert client.get(MEMBERS, headers=agent.headers).status_code == 200
    denied = client.post(
        MEMBERS,
        headers=agent.headers,
        json={
            "email": "x@abc.com",
            "role": "viewer",
            "full_name": "X",
            "password": "long-enough-pass",
        },
    )
    assert denied.status_code == 403
    assert denied.json()["error"]["code"] == "PERMISSION_DENIED"
    assert (
        client.patch(
            "/api/v1/organizations/current", headers=agent.headers, json={"name": "Hax"}
        ).status_code
        == 403
    )
    assert client.get("/api/v1/audit-logs", headers=agent.headers).status_code == 403


def test_add_member_requires_details_for_new_users(client: TestClient) -> None:
    owner = register_account(client)
    response = client.post(
        MEMBERS, headers=owner.headers, json={"email": "new@abc.com", "role": "agent"}
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "NEW_USER_DETAILS_REQUIRED"


def test_cannot_add_same_member_twice(client: TestClient) -> None:
    owner = register_account(client)
    add_member(client, owner, "dup@abc.com", "agent")
    again = client.post(
        MEMBERS, headers=owner.headers, json={"email": "DUP@abc.com", "role": "agent"}
    )
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "MEMBER_ALREADY_EXISTS"


def test_admin_cannot_grant_owner_or_demote_owner(client: TestClient) -> None:
    owner = register_account(client)
    admin = add_member(client, owner, "admin@abc.com", "admin")

    grant = client.post(
        MEMBERS,
        headers=admin.headers,
        json={
            "email": "o2@abc.com",
            "role": "owner",
            "full_name": "O",
            "password": "long-enough-pass",
        },
    )
    assert grant.status_code == 403
    assert grant.json()["error"]["code"] == "CANNOT_MANAGE_ROLE"

    owner_member_id = next(
        m["id"]
        for m in client.get(MEMBERS, headers=admin.headers).json()["items"]
        if m["role"] == "owner"
    )
    assert (
        client.patch(
            f"{MEMBERS}/{owner_member_id}", headers=admin.headers, json={"role": "viewer"}
        ).status_code
        == 403
    )
    assert client.delete(f"{MEMBERS}/{owner_member_id}", headers=admin.headers).status_code == 403


def test_last_owner_cannot_be_demoted_or_removed(client: TestClient) -> None:
    owner = register_account(client)
    owner_member_id = client.get(MEMBERS, headers=owner.headers).json()["items"][0]["id"]

    demote = client.patch(
        f"{MEMBERS}/{owner_member_id}", headers=owner.headers, json={"role": "admin"}
    )
    assert demote.status_code == 409 and demote.json()["error"]["code"] == "LAST_OWNER"
    remove = client.delete(f"{MEMBERS}/{owner_member_id}", headers=owner.headers)
    assert remove.status_code == 409


def test_removed_member_loses_access_immediately(client: TestClient) -> None:
    owner = register_account(client)
    agent = add_member(client, owner, "agent@abc.com", "agent")
    agent_member_id = next(
        m["id"]
        for m in client.get(MEMBERS, headers=owner.headers).json()["items"]
        if m["email"] == "agent@abc.com"
    )

    assert client.delete(f"{MEMBERS}/{agent_member_id}", headers=owner.headers).status_code == 204
    # Their access token has not expired, but membership no longer exists.
    assert client.get("/api/v1/auth/me", headers=agent.headers).status_code == 401
    assert (
        client.post("/api/v1/auth/refresh", json={"refresh_token": agent.refresh_token}).status_code
        == 401
    )


def test_role_change_takes_effect_on_next_request(client: TestClient) -> None:
    owner = register_account(client)
    agent = add_member(client, owner, "agent@abc.com", "agent")
    member_id = next(
        m["id"]
        for m in client.get(MEMBERS, headers=owner.headers).json()["items"]
        if m["email"] == "agent@abc.com"
    )
    assert client.get("/api/v1/audit-logs", headers=agent.headers).status_code == 403

    assert (
        client.patch(
            f"{MEMBERS}/{member_id}", headers=owner.headers, json={"role": "admin"}
        ).status_code
        == 200
    )
    assert (
        client.get("/api/v1/audit-logs", headers=agent.headers).status_code == 200
    )  # same token, new role


def test_actions_are_audited_with_details_and_filters(client: TestClient) -> None:
    owner = register_account(client)
    add_member(client, owner, "agent@abc.com", "agent")
    client.patch(
        "/api/v1/organizations/current", headers=owner.headers, json={"name": "ABC Renamed"}
    )

    logs = client.get("/api/v1/audit-logs", headers=owner.headers).json()
    actions = [entry["action"] for entry in logs["items"]]
    assert {"organization.created", "member.added", "organization.updated", "auth.login"} <= set(
        actions
    )

    renamed = client.get(
        "/api/v1/audit-logs", params={"action": "organization.updated"}, headers=owner.headers
    ).json()
    assert renamed["total"] == 1
    assert renamed["items"][0]["details"] == {
        "old_name": "ABC Insurance",
        "new_name": "ABC Renamed",
    }


def test_update_organization_rejects_blank_name(client: TestClient) -> None:
    owner = register_account(client)
    assert (
        client.patch(
            "/api/v1/organizations/current", headers=owner.headers, json={"name": "   "}
        ).status_code
        == 422
    )
