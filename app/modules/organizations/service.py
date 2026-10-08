"""Business logic for the current organization (tenant)."""

import re
import secrets

from sqlalchemy.orm import Session

from app.core.errors import ErrorCode, NotFoundError
from app.modules.audit.constants import AuditAction
from app.modules.audit.service import AuditService
from app.modules.auth.deps import TenantContext
from app.modules.organizations.models import Organization
from app.modules.organizations.repository import OrganizationRepository

SLUG_MAX_BASE_LENGTH = 60


def make_slug(name: str) -> str:
    """Build a unique URL-friendly slug from an organization name.

    Example: "ABC Insurance!" -> "abc-insurance-3f9a1c".

    Why a random suffix: two companies may share a name; the suffix avoids a
    collision check/retry loop (24 bits of randomness; the unique DB index is
    the final guarantee).

    Args:
        name: the display name.
    Returns:
        lower-case ascii words joined by dashes + "-" + 6 hex characters.
    """
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:SLUG_MAX_BASE_LENGTH] or "org"
    return f"{base}-{secrets.token_hex(3)}"


class OrganizationService:
    """Read and update the caller's own organization."""

    def __init__(self, session: Session, ctx: TenantContext) -> None:
        """Bind to the request session and the authenticated caller."""
        self.session = session
        self.ctx = ctx
        self.repo = OrganizationRepository(session)

    def get_current(self) -> Organization:
        """Return the caller's organization.

        Returns:
            The Organization for ctx.organization_id.
        Raises:
            NotFoundError: only if the row vanished mid-request (should not happen).
        Note: the id comes from the verified context, so a caller can never
        request another tenant's organization.
        """
        organization = self.session.get(Organization, self.ctx.organization_id)
        if organization is None:
            raise NotFoundError(
                ErrorCode.ORGANIZATION_NOT_FOUND, "Organization could not be found."
            )
        return organization

    def update_current(self, name: str) -> Organization:
        """Rename the caller's organization and audit the change.

        Flow: load org -> change name -> write audit entry -> commit once.

        Args:
            name: the new, already validated name.
        Returns:
            The updated organization.
        """
        organization = self.get_current()
        old_name = organization.name
        organization.name = name
        AuditService(self.session, self.ctx.organization_id).record(
            AuditAction.ORG_UPDATED,
            actor_user_id=self.ctx.user_id,
            resource_type="organization",
            resource_id=organization.id,
            details={"old_name": old_name, "new_name": name},
            ip_address=self.ctx.ip_address,
        )
        self.session.commit()
        return organization


def create_organization(session: Session, name: str) -> Organization:
    """Create a new tenant (used by registration).

    Does not commit: registration creates the org, user, membership and tokens
    in a single transaction.

    Args:
        session: the caller's session.
        name: display name.
    Returns:
        The staged (flushed) Organization.
    """
    return OrganizationRepository(session).add(Organization(name=name, slug=make_slug(name)))
