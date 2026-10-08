"""Base class that makes cross-tenant data access structurally difficult.

Responsibility: every repository for a tenant-owned table inherits from
`TenantRepository`. It is constructed with the caller's organization_id and
every query goes through `_scoped()`, which appends
`WHERE organization_id = <caller's org>`.

Why: relying on each developer to remember the filter in each query is how
data leaks happen. Here the safe path is the default path.
"""

import uuid
from typing import Any

from sqlalchemy import Select
from sqlalchemy.orm import Session


class TenantRepository:
    """Parent for repositories of tables that carry an `organization_id`."""

    # Subclasses set this to their ORM model (which must use TenantMixin).
    model: type[Any]

    def __init__(self, session: Session, organization_id: uuid.UUID) -> None:
        """Bind the repository to ONE tenant for its whole lifetime.

        Args:
            session: the request's database session.
            organization_id: the tenant taken from the authenticated context
                (never from user-supplied input).
        """
        self.session = session
        self.organization_id = organization_id

    def _scoped(self, statement: Select[Any]) -> Select[Any]:
        """Restrict a SELECT to the bound tenant.

        Args:
            statement: any select on `self.model`.
        Returns:
            The same statement with the tenant filter added.
        Important: call this on EVERY select in subclasses.
        """
        return statement.where(self.model.organization_id == self.organization_id)
