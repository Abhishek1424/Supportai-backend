"""SQLAlchemy declarative base and reusable column mixins.

Responsibility: one shared `Base` (so Alembic sees every table) plus mixins
for columns that nearly every table needs.
"""

import uuid
from datetime import UTC, datetime

from sqlalchemy import DateTime, ForeignKey, MetaData
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column

# Explicit constraint names make Alembic migrations deterministic and let us
# drop/alter constraints by name later.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


def utcnow() -> datetime:
    """Current time as timezone-aware UTC (never use naive datetimes)."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Parent of every ORM model."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class IdMixin:
    """UUID primary key.

    Why UUID: IDs are unguessable (no enumeration attacks) and can be generated
    without a database round-trip.
    """

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


class TimestampMixin:
    """created_at / updated_at maintained automatically."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


class TenantMixin:
    """Marks a table as tenant-owned by adding a mandatory organization_id.

    Every table with this mixin MUST only be queried through a
    `TenantRepository` (see tenant_repository.py), which always filters on it.
    """

    @declared_attr
    def organization_id(cls) -> Mapped[uuid.UUID]:
        """Indexed, non-null foreign key to the owning organization."""
        return mapped_column(
            ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
        )
