"""Audit service: the one way application code writes audit entries."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.core.pagination import PageParams
from app.modules.audit.constants import AuditAction
from app.modules.audit.models import AuditLog
from app.modules.audit.repository import AuditRepository


class AuditService:
    """Records and reads audit entries."""

    def __init__(self, session: Session, organization_id: uuid.UUID) -> None:
        """Bind to a session and a tenant (entries are always written to this tenant)."""
        self.repo = AuditRepository(session, organization_id)
        self.organization_id = organization_id

    def record(
        self,
        action: AuditAction,
        *,
        actor_user_id: uuid.UUID | None,
        resource_type: str,
        resource_id: uuid.UUID | None = None,
        details: dict[str, Any] | None = None,
        ip_address: str | None = None,
    ) -> None:
        """Append an audit entry inside the CALLER's transaction.

        Why it does not commit: the audit row and the action it describes must
        succeed or fail together. If the business operation rolls back, no
        misleading log remains; if it commits, the log is guaranteed to exist.

        Args:
            action: what happened.
            actor_user_id: who did it (None for system actions).
            resource_type: kind of object affected, e.g. "member".
            resource_id: id of the affected object.
            details: small JSON context such as {"old_role": "agent", "new_role": "admin"}.
                Must never contain passwords, tokens or other secrets.
            ip_address: caller IP for forensic use.
        """
        self.repo.add(
            AuditLog(
                organization_id=self.organization_id,
                actor_user_id=actor_user_id,
                action=action.value,
                resource_type=resource_type,
                resource_id=resource_id,
                details=details or {},
                ip_address=ip_address,
            )
        )

    def search(
        self,
        params: PageParams,
        *,
        action: str | None = None,
        actor_user_id: uuid.UUID | None = None,
        resource_type: str | None = None,
        created_from: datetime | None = None,
        created_to: datetime | None = None,
    ) -> tuple[list[AuditLog], int]:
        """List this tenant's audit entries, newest first, with optional filters.

        Thin pass-through to the repository; it exists so routes depend on the
        service layer only (Route -> Service -> Repository).

        Returns:
            (entries for the requested page, total matching entries).
        """
        return self.repo.search(
            params,
            action=action,
            actor_user_id=actor_user_id,
            resource_type=resource_type,
            created_from=created_from,
            created_to=created_to,
        )
