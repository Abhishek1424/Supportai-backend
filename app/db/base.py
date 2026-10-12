# What is this file?   The base class of all database table classes + shared columns.
# Flutter/Dart idea:   with Drift/Floor you write table classes. `Base` is the parent
#                      of all of them. The "mixins" below are like Dart `mixin`s that
#                      add common columns (id, timestamps, organization_id).
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
# Gives constraints and indexes predictable names, so database migrations are stable.
NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


# Current time with time zone (UTC). We never use time without a zone.
def utcnow() -> datetime:
    """Current time as timezone-aware UTC (never use naive datetimes)."""
    return datetime.now(UTC)


# Parent of every table class (ORM model). ORM = maps a class to a database table.
class Base(DeclarativeBase):
    """Parent of every ORM model."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# Adds a UUID `id` column. UUID = long random id that cannot be guessed.
# Dart idea: `mixin IdMixin { final String id = Uuid().v4(); }`.
class IdMixin:
    """UUID primary key.

    Why UUID: IDs are unguessable (no enumeration attacks) and can be generated
    without a database round-trip.
    """

    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)


# Adds created_at and updated_at. `onupdate` refreshes updated_at on every change.
class TimestampMixin:
    """created_at / updated_at maintained automatically."""

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False
    )


# IMPORTANT for security. Adds `organization_id` to a table = "this row belongs
# to this company". All tenant data must be filtered by it (see db/tenant_repository.py).
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
