# What is this file?   Business rules for managing team members.
# Rules in here:       no giving higher roles than your own; the last owner cannot be
#                      removed or demoted; every change writes an audit entry.
# Flutter/Dart idea:   a `MemberService`. Notice it gets a MemberRepository that is
#                      already limited to the caller's company. So a member id from
#                      another company is simply "not found" (404).
"""Business logic for managing the team members of an organization."""

import uuid

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.errors import (
    BadRequestError,
    ConflictError,
    ErrorCode,
    ForbiddenError,
    NotFoundError,
)
from app.core.pagination import PageParams
from app.core.security import hash_password
from app.modules.audit.constants import AuditAction
from app.modules.audit.service import AuditService
from app.modules.auth.deps import TenantContext
from app.modules.organizations.models import OrganizationMember
from app.modules.organizations.repository import MemberRepository
from app.modules.organizations.schemas import MemberCreate, MemberListQuery
from app.modules.rbac.constants import Role, can_manage_role_change
from app.modules.users.models import User
from app.modules.users.repository import UserRepository


# Constructor builds the repositories it needs from the session and context.
class MemberService:
    """List, add, re-role and remove members of the CALLER's organization.

    Every method is tenant-safe because `MemberRepository` is bound to
    ctx.organization_id: a member id from another tenant simply is not found.
    """

    def __init__(self, session: Session, ctx: TenantContext) -> None:
        """Bind to the request session and the authenticated caller."""
        self.session = session
        self.ctx = ctx
        self.members = MemberRepository(session, ctx.organization_id)
        self.users = UserRepository(session)
        self.audit = AuditService(session, ctx.organization_id)

    # Just passes search options to the repository.
    def list_members(
        self, params: PageParams, query: MemberListQuery
    ) -> tuple[list[OrganizationMember], int]:
        """Return one page of members plus the total count (search + sort supported)."""
        return self.members.search(
            params, q=query.q, sort_by=query.sort_by, sort_order=query.sort_order
        )

    # Flow: check role rule -> find or create user -> check not already a member
    #       -> create membership -> audit -> commit.
    # Edge case: two requests at once; the unique constraint catches it -> 409.
    def add_member(self, data: MemberCreate) -> OrganizationMember:
        """Add a person to the organization with a role.

        Flow:
        1. Check the caller may grant this role (no privilege escalation).
        2. Find the user by email; if missing, create the account (needs full_name + password).
        3. Refuse if they are already a member.
        4. Create the membership, write an audit entry, commit once.

        Raises:
            ForbiddenError: caller tries to grant a role above their own.
            BadRequestError: new email but no full_name/password supplied.
            ConflictError: the person is already in this organization.
        """
        if not can_manage_role_change(self.ctx.role, None, data.role):
            raise ForbiddenError(ErrorCode.CANNOT_MANAGE_ROLE, "You cannot assign that role.")

        user = self.users.get_by_email(data.email)
        if user is None:
            if not data.full_name or not data.password:
                raise BadRequestError(
                    ErrorCode.NEW_USER_DETAILS_REQUIRED,
                    "full_name and password are required for a new user.",
                )
            user = self.users.add(
                User(
                    email=data.email,
                    full_name=data.full_name,
                    password_hash=hash_password(data.password),
                )
            )
        elif self.members.get_by_user_id(user.id) is not None:
            raise ConflictError(ErrorCode.MEMBER_ALREADY_EXISTS, "This person is already a member.")

        try:
            member = self.members.add(
                OrganizationMember(
                    organization_id=self.ctx.organization_id, user_id=user.id, role=data.role
                )
            )
        except IntegrityError as exc:
            # Two concurrent requests added the same person; the unique constraint caught it.
            self.session.rollback()
            raise ConflictError(
                ErrorCode.MEMBER_ALREADY_EXISTS, "This person is already a member."
            ) from exc

        self._audit(
            AuditAction.MEMBER_ADDED, member, {"role": data.role.value, "email": user.email}
        )
        self.session.commit()
        return member

    # Flow: load member (own company only) -> rank rule -> last-owner rule -> change ->
    #   audit -> commit.
    def change_role(self, member_id: uuid.UUID, new_role: Role) -> OrganizationMember:
        """Change a member's role.

        Business rules: see `can_manage_role_change` (rank checks) and the
        last-owner rule: an organization must always keep at least one owner.

        Raises:
            NotFoundError: no such member in THIS organization (also for other tenants' ids).
            ForbiddenError: rank rule violated.
            ConflictError: would demote the last owner.
        """
        member = self._get_or_404(member_id)
        if not can_manage_role_change(self.ctx.role, member.role, new_role):
            raise ForbiddenError(ErrorCode.CANNOT_MANAGE_ROLE, "You cannot change this role.")
        if member.role == Role.OWNER and new_role != Role.OWNER:
            self._ensure_not_last_owner()

        old_role = member.role
        member.role = new_role
        self._audit(
            AuditAction.MEMBER_ROLE_CHANGED,
            member,
            {"old_role": old_role.value, "new_role": new_role.value},
        )
        self.session.commit()
        return member

    # Deletes the membership only (not the user account). The person's token stops working
    #   at once.
    def remove_member(self, member_id: uuid.UUID) -> None:
        """Remove a member from the organization (their user account remains).

        Effect: their access tokens stop working immediately, because every
        request re-checks membership in the database.

        Raises:
            NotFoundError / ForbiddenError / ConflictError: as in `change_role`.
        """
        member = self._get_or_404(member_id)
        if not can_manage_role_change(self.ctx.role, member.role, member.role):
            raise ForbiddenError(ErrorCode.CANNOT_MANAGE_ROLE, "You cannot remove this member.")
        if member.role == Role.OWNER:
            self._ensure_not_last_owner()

        self._audit(AuditAction.MEMBER_REMOVED, member, {"role": member.role.value})
        self.members.delete(member)
        self.session.commit()

    # Helper: returns the member or throws NotFoundError. Same message for 'missing' and
    #   'other company'.
    def _get_or_404(self, member_id: uuid.UUID) -> OrganizationMember:
        """Load a member of this tenant or raise NotFoundError (never leaks other tenants)."""
        member = self.members.get(member_id)
        if member is None:
            raise NotFoundError(ErrorCode.MEMBER_NOT_FOUND, "Member could not be found.")
        return member

    # A company must always keep at least one owner.
    def _ensure_not_last_owner(self) -> None:
        """Raise if the organization has only one owner left.

        Called before demoting/removing an owner. Without it an organization
        could become impossible to administer.
        """
        if self.members.count_with_role(Role.OWNER) <= 1:
            raise ConflictError(
                ErrorCode.LAST_OWNER, "An organization must keep at least one owner."
            )

    # Small helper to write a member audit entry. Avoids repeating the same code.
    def _audit(
        self, action: AuditAction, member: OrganizationMember, details: dict[str, str]
    ) -> None:
        """Write a member-related audit entry attributed to the caller."""
        self.audit.record(
            action,
            actor_user_id=self.ctx.user_id,
            resource_type="member",
            resource_id=member.id,
            details=details,
            ip_address=self.ctx.ip_address,
        )
