# What is this file?   The security guard for protected endpoints.
# Why?                 Turns "Authorization: Bearer <token>" into a trusted TenantContext.
# How it is used:      endpoints write `Depends(require_permission(...))` and the
#                      framework runs this code first.
# Flutter/Dart idea:   like an auth interceptor + permission check, but on the SERVER.
#                      TenantContext ~ an immutable `CurrentUser` object you pass around.
# Security rule: the company id comes ONLY from the verified token + database.
#                Never from the request body or query.
"""Authentication & authorization dependencies shared by every protected route.

Responsibility: turn "Authorization: Bearer <jwt>" into a trusted
`TenantContext` (who is calling, in which organization, with which
permissions) and provide `require_permission()` to guard routes.

This is the backend authorization layer the product rules demand: tenant
identity comes ONLY from the verified token + database membership, never from
request bodies, query params or headers the client controls.
"""

import uuid
from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.errors import ErrorCode, ForbiddenError, UnauthorizedError
from app.core.security import decode_access_token
from app.db.session import get_db
from app.modules.organizations.repository import OrganizationRepository
from app.modules.rbac.constants import Permission, Role, permissions_for
from app.modules.users.models import User

# Shortcut: `db: DbDep` means 'give me a database Session for this request' (see
#   db/session.py).
DbDep = Annotated[Session, Depends(get_db)]

# auto_error=False so WE return our standard error body when the header is missing.
# Reads the `Authorization: Bearer ...` header. `auto_error=False` lets us return our own
#   error JSON.
_bearer_scheme = HTTPBearer(auto_error=False)


# An immutable data class. Dart idea: all fields `final`.
@dataclass(frozen=True)
class TenantContext:
    """Everything a service needs to know about the caller. Immutable."""

    user: User
    organization_id: uuid.UUID
    role: Role
    permissions: frozenset[Permission]
    ip_address: str | None

    @property
    def user_id(self) -> uuid.UUID:
        """Shortcut for the caller's user id."""
        return self.user.id


# Flow on EVERY protected request:
#  1. Read the token from the header. Missing -> 401.
#  2. Verify signature + expiry (core/security.py).
#  3. Load the user's membership from the DATABASE. This is why removing a member
#     or suspending a company works immediately, even if the token is not expired.
#  4. Check the user and company are active.
#  5. Save user_id / organization_id on request.state (the logger prints them).
#  6. Return TenantContext (user, company id, role, permissions).
# Flutter idea: the function that builds "who is the current user?" for each call.
def get_current_context(
    request: Request,
    db: DbDep,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer_scheme)],
) -> TenantContext:
    """Authenticate the request and build the caller's TenantContext.

    Flow:
    1. Read and verify the bearer JWT (signature, expiry, type).
    2. Load the membership (user + organization) for the token's user/org pair
       from the DATABASE. This makes revocation immediate: remove a member or
       suspend an organization and their still-unexpired token stops working.
    3. Reject inactive users and suspended organizations.
    4. Store user_id / organization_id on request.state for request logging.

    Raises:
        UnauthorizedError: missing/invalid token, or the membership no longer exists.
        ForbiddenError: the organization is suspended or the user is deactivated.
    """
    if credentials is None:
        raise UnauthorizedError(ErrorCode.NOT_AUTHENTICATED, "Authentication required.")
    claims = decode_access_token(credentials.credentials)

    membership = OrganizationRepository(db).get_membership(claims.user_id, claims.organization_id)
    if membership is None:
        raise UnauthorizedError(ErrorCode.INVALID_TOKEN, "Invalid or expired access token.")
    if not membership.user.is_active:
        raise ForbiddenError(ErrorCode.PERMISSION_DENIED, "This account is disabled.")
    if not membership.organization.is_active:
        raise ForbiddenError(ErrorCode.ORGANIZATION_SUSPENDED, "This organization is suspended.")

    request.state.user_id = str(membership.user_id)
    request.state.organization_id = str(membership.organization_id)
    return TenantContext(
        user=membership.user,
        organization_id=membership.organization_id,
        role=membership.role,
        permissions=permissions_for(membership.role),
        ip_address=request.client.host if request.client else None,
    )


# A function that RETURNS a function (a "factory"). Dart idea: a closure.
# Use:  `ctx = Depends(require_permission(Permission.MEMBERS_MANAGE))`.
# If the role does not have the permission -> 403 and the endpoint code never runs.
def require_permission(permission: Permission):  # type: ignore[no-untyped-def]
    """Build a dependency that only lets callers holding `permission` through.

    Usage: `ctx: TenantContext = Depends(require_permission(Permission.AUDIT_READ))`

    Why a factory: each route declares exactly which permission it needs, in
    its own signature, so a missing check is visible in code review.

    Returns:
        A dependency function that yields the TenantContext or raises ForbiddenError.
    """

    def dependency(ctx: Annotated[TenantContext, Depends(get_current_context)]) -> TenantContext:
        """Check the permission against the caller's role-derived permission set."""
        if permission not in ctx.permissions:
            raise ForbiddenError(
                ErrorCode.PERMISSION_DENIED, "You do not have permission to perform this action."
            )
        return ctx

    return dependency
