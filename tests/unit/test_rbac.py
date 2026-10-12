# Unit tests for role and permission rules. Pure functions.
"""Unit tests for the role/permission rules."""

import pytest

from app.modules.rbac.constants import Permission, Role, can_manage_role_change, permissions_for


def test_owner_and_admin_have_every_permission() -> None:
    for role in (Role.OWNER, Role.ADMIN):
        assert permissions_for(role) == frozenset(Permission)


@pytest.mark.parametrize("role", [Role.AGENT, Role.VIEWER])
def test_agents_and_viewers_cannot_manage_or_read_audit(role: Role) -> None:
    permissions = permissions_for(role)
    assert Permission.MEMBERS_MANAGE not in permissions
    assert Permission.AUDIT_READ not in permissions
    assert Permission.ORG_UPDATE not in permissions


def test_admin_cannot_create_or_touch_owners() -> None:
    assert not can_manage_role_change(Role.ADMIN, None, Role.OWNER)
    assert not can_manage_role_change(Role.ADMIN, Role.OWNER, Role.AGENT)


def test_admin_can_manage_lower_roles() -> None:
    assert can_manage_role_change(Role.ADMIN, None, Role.AGENT)
    assert can_manage_role_change(Role.ADMIN, Role.AGENT, Role.ADMIN)


def test_owner_can_do_everything() -> None:
    assert can_manage_role_change(Role.OWNER, Role.OWNER, Role.VIEWER)
    assert can_manage_role_change(Role.OWNER, None, Role.OWNER)
