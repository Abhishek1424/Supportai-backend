# What is this file?   Queries for companies and members.
# Two repositories:    OrganizationRepository  - lookups needed BEFORE we know the company
#                                                (login, token check).
#                      MemberRepository        - tenant-safe; always limited to one company.
"""Data access for organizations and memberships."""

import uuid

from sqlalchemy import asc, desc, func, select
from sqlalchemy.orm import Session

from app.core.pagination import PageParams
from app.db.tenant_repository import TenantRepository
from app.modules.organizations.models import Organization, OrganizationMember
from app.modules.users.models import User

# Allowlist mapping API sort keys to columns. User input never becomes SQL text.
# Allow-list: the app sends sort_by as text; we map it to a real column. User text never
#   goes into SQL directly.
MEMBER_SORT_COLUMNS = {
    "created_at": OrganizationMember.created_at,
    "role": OrganizationMember.role,
    "email": User.email,
    "full_name": User.full_name,
}


# Cross-company lookups. Use it only before authentication.
class OrganizationRepository:
    """Cross-tenant lookups needed BEFORE a tenant context exists (login, token check).

    Deliberately small: anything that runs after authentication must use the
    tenant-scoped repositories instead.
    """

    def __init__(self, session: Session) -> None:
        """Bind to the request's session."""
        self.session = session

    def add(self, organization: Organization) -> Organization:
        """Stage a new organization and flush so its id is available."""
        self.session.add(organization)
        self.session.flush()
        return organization

    # Used on EVERY request to re-check the user is still a member.
    def get_membership(
        self, user_id: uuid.UUID, organization_id: uuid.UUID
    ) -> OrganizationMember | None:
        """Find one user's membership in one organization (with user + org loaded).

        Used on every authenticated request to re-validate the token's claims.
        """
        return self.session.scalar(
            select(OrganizationMember).where(
                OrganizationMember.user_id == user_id,
                OrganizationMember.organization_id == organization_id,
            )
        )

    def list_memberships_for_user(self, user_id: uuid.UUID) -> list[OrganizationMember]:
        """All organizations a user belongs to, oldest first (login picks the first)."""
        return list(
            self.session.scalars(
                select(OrganizationMember)
                .where(OrganizationMember.user_id == user_id)
                .order_by(OrganizationMember.created_at)
            ).all()
        )


# Child of TenantRepository: all queries here include the company filter.
class MemberRepository(TenantRepository):
    """Tenant-scoped access to OrganizationMember rows."""

    model = OrganizationMember

    def add(self, member: OrganizationMember) -> OrganizationMember:
        """Stage a new membership and flush (surfaces duplicate-member errors immediately)."""
        self.session.add(member)
        self.session.flush()
        return member

    def get(self, member_id: uuid.UUID) -> OrganizationMember | None:
        """Fetch a member by id, only if it belongs to this tenant (else None)."""
        statement = self._scoped(select(OrganizationMember)).where(
            OrganizationMember.id == member_id
        )
        member: OrganizationMember | None = self.session.scalar(statement)
        return member

    def get_by_user_id(self, user_id: uuid.UUID) -> OrganizationMember | None:
        """Fetch this tenant's membership for a given user, if any."""
        statement = self._scoped(select(OrganizationMember)).where(
            OrganizationMember.user_id == user_id
        )
        member: OrganizationMember | None = self.session.scalar(statement)
        return member

    def count_with_role(self, role: object) -> int:
        """Count members holding a role (used to protect the last owner)."""
        return (
            self.session.scalar(
                self._scoped(select(func.count()).select_from(OrganizationMember)).where(
                    OrganizationMember.role == role
                )
            )
            or 0
        )

    def delete(self, member: OrganizationMember) -> None:
        """Remove a membership (the user account itself is kept)."""
        self.session.delete(member)
        self.session.flush()

    # Search + sort + page. `icontains(autoescape=True)` = case-insensitive 'contains' that
    #   treats % and _ as normal text.
    def search(
        self, params: PageParams, *, q: str | None, sort_by: str, sort_order: str
    ) -> tuple[list[OrganizationMember], int]:
        """Paginated, searchable, sortable member list.

        Args:
            params: pagination.
            q: optional text matched (case-insensitively, wildcard-escaped) against email and name.
            sort_by: key from MEMBER_SORT_COLUMNS (already validated by the schema).
            sort_order: "asc" or "desc".
        Returns:
            (members on this page, total matching members).
        """
        base = self._scoped(select(OrganizationMember)).join(
            User, User.id == OrganizationMember.user_id
        )
        if q:
            base = base.where(
                User.email.icontains(q, autoescape=True)
                | User.full_name.icontains(q, autoescape=True)
            )
        total = self.session.scalar(select(func.count()).select_from(base.subquery())) or 0
        direction = asc if sort_order == "asc" else desc
        rows = self.session.scalars(
            base.order_by(direction(MEMBER_SORT_COLUMNS[sort_by]), OrganizationMember.id)
            .limit(params.page_size)
            .offset(params.offset)
        ).all()
        return list(rows), total
