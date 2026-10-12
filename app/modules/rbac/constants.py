# What is this file?   Who can do what. Roles and permissions, written in code.
# Why?                 One clear place to read the rules, and easy to test.
# Flutter/Dart idea:   enums + a const Map<Role, Set<Permission>>.
# How it is used:      auth/deps.py turns the user's role into a permission set.
#                      Endpoints ask for a PERMISSION (not a role), like
#                      `require_permission(Permission.AUDIT_READ)`.
# The React web app has a copy of these rules in lib/permissions.ts, only to hide buttons.
"""Roles and permissions (RBAC).

Responsibility: the single source of truth for "which role may do what".

Design choice: roles and their permissions live in CODE, not in database
tables. They change rarely and with a deploy, they can be unit-tested, and
there is no seed data to keep in sync. If customers later need custom roles,
this can move to tables without changing the `require_permission()` API.
"""

from enum import StrEnum


# Dart: `enum Role { owner, admin, agent, viewer }`. The text value is saved in the
#   database.
class Role(StrEnum):
    """Roles a member can hold inside one organization."""

    OWNER = "owner"
    ADMIN = "admin"
    AGENT = "agent"
    VIEWER = "viewer"


# Small actions. Naming style is `thing:action`.
class Permission(StrEnum):
    """Fine-grained actions. Routes check permissions, never roles directly."""

    ORG_READ = "org:read"
    ORG_UPDATE = "org:update"
    MEMBERS_READ = "members:read"
    MEMBERS_MANAGE = "members:manage"
    AUDIT_READ = "audit:read"


# Dart: `const Map<Role, Set<Permission>>`. `frozenset` = an immutable Set.
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    Role.OWNER: frozenset(Permission),
    Role.ADMIN: frozenset(Permission),
    Role.AGENT: frozenset({Permission.ORG_READ, Permission.MEMBERS_READ}),
    Role.VIEWER: frozenset({Permission.ORG_READ, Permission.MEMBERS_READ}),
}

# Higher number = more powerful. Used to stop people granting or editing roles
# above their own level.
# A higher number means more power. Used so nobody can give a role higher than their own.
ROLE_RANK: dict[Role, int] = {Role.VIEWER: 1, Role.AGENT: 2, Role.ADMIN: 3, Role.OWNER: 4}


# Returns the permission set of a role.
def permissions_for(role: Role) -> frozenset[Permission]:
    """Return the permissions granted by a role.

    Args:
        role: the member's role.
    Returns:
        An immutable set of permissions.
    """
    return ROLE_PERMISSIONS[role]


# Business rule: you can only touch people at or below your level, and only
# give roles at or below your level. So an admin cannot create or remove an owner.
# Pure function (no database). That is why it is easy to unit test.
def can_manage_role_change(actor: Role, current: Role | None, new: Role) -> bool:
    """Decide whether `actor` may create/edit a member so they end up with `new`.

    Business rule: you may only touch members at or below your own rank, and
    only grant roles at or below your own rank. Therefore only an OWNER can
    create, demote or remove another owner, and an ADMIN cannot promote anyone
    (or themselves) to owner.

    Args:
        actor: role of the person performing the action.
        current: the target's existing role, or None when adding a new member.
        new: the role the target will have after the action.
    Returns:
        True if allowed.
    """
    actor_rank = ROLE_RANK[actor]
    if current is not None and ROLE_RANK[current] > actor_rank:
        return False
    return ROLE_RANK[new] <= actor_rank
