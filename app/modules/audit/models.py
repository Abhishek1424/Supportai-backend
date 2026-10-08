"""Audit log model."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, IdMixin, TenantMixin, utcnow


class AuditLog(IdMixin, TenantMixin, Base):
    """Append-only record of a security-relevant action.

    Never updated or deleted by application code. It stores ids rather than
    foreign keys to users so history survives user deletion.
    """

    __tablename__ = "audit_logs"

    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(index=True)
    action: Mapped[str] = mapped_column(String(100), index=True)
    resource_type: Mapped[str] = mapped_column(String(50))
    resource_id: Mapped[uuid.UUID | None] = mapped_column()
    # Small structured context (e.g. old/new role). Never put secrets here.
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    ip_address: Mapped[str | None] = mapped_column(String(45))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, index=True
    )
