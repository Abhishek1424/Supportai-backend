"""Data access for audit logs (tenant-scoped)."""

import uuid
from datetime import datetime

from sqlalchemy import func, select

from app.core.pagination import PageParams
from app.db.tenant_repository import TenantRepository
from app.modules.audit.models import AuditLog


class AuditRepository(TenantRepository):
    """Reads and appends audit entries for ONE organization."""

    model = AuditLog

    def add(self, entry: AuditLog) -> None:
        """Stage a new entry. The caller's transaction commits it together with the action."""
        self.session.add(entry)

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
        """List entries newest-first with optional filters.

        Args:
            params: pagination.
            action / actor_user_id / resource_type: exact-match filters.
            created_from / created_to: inclusive time range.
        Returns:
            (rows for this page, total rows matching the filters).
        """
        filters = []
        if action:
            filters.append(AuditLog.action == action)
        if actor_user_id:
            filters.append(AuditLog.actor_user_id == actor_user_id)
        if resource_type:
            filters.append(AuditLog.resource_type == resource_type)
        if created_from:
            filters.append(AuditLog.created_at >= created_from)
        if created_to:
            filters.append(AuditLog.created_at <= created_to)

        total = self.session.scalar(
            self._scoped(select(func.count()).select_from(AuditLog)).where(*filters)
        )
        rows = self.session.scalars(
            self._scoped(select(AuditLog))
            .where(*filters)
            .order_by(AuditLog.created_at.desc(), AuditLog.id)
            .limit(params.page_size)
            .offset(params.offset)
        ).all()
        return list(rows), total or 0
