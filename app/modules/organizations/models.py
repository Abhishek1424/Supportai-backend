# What is this file?   Tables for companies (Organization) and for who belongs to
#                      which company with which role (OrganizationMember).
# Flutter/Dart idea:   two table classes. OrganizationMember is a "join table"
#                      with extra data (the role).
# Picture:  User --< OrganizationMember >-- Organization     (many-to-many)
"""Organization (tenant) and membership models."""

import uuid
from typing import TYPE_CHECKING

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy import Enum as SAEnum
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, IdMixin, TenantMixin, TimestampMixin
from app.modules.rbac.constants import Role

if TYPE_CHECKING:
    from app.modules.users.models import User


# A company = a TENANT. Its id is the 'company id' used all over the project.
class Organization(IdMixin, TimestampMixin, Base):
    """A client company = one tenant. Its `id` is the tenant id used everywhere."""

    __tablename__ = "organizations"

    name: Mapped[str] = mapped_column(String(200))
    # URL-friendly unique identifier, e.g. "abc-insurance-3f9a1c".
    slug: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    # False = suspended by a platform admin; members can no longer use the API.
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


# One row = one person in one company with one role.
class OrganizationMember(IdMixin, TimestampMixin, TenantMixin, Base):
    """Links a User to an Organization with a Role (many-to-many with data)."""

    __tablename__ = "organization_members"
    # A person can be in a company only once (unique pair).
    __table_args__ = (UniqueConstraint("organization_id", "user_id"),)

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    # Stored as plain text ("owner", "admin", ...) with no DB enum type, so adding
    # a role later never needs an ALTER TYPE migration.
    # Saved as plain text like 'owner'. Using text (not a database enum) makes adding roles
    #   easy.
    role: Mapped[Role] = mapped_column(
        SAEnum(Role, native_enum=False, length=20, values_callable=lambda e: [m.value for m in e])
    )

    # `relationship` = load the linked row automatically. Like a foreign-key object field.
    #   `lazy="joined"` loads it in the same query.
    user: Mapped["User"] = relationship(lazy="joined")
    organization: Mapped[Organization] = relationship(lazy="joined")

    # A property is a getter. Dart: `String get email => user.email;`.
    @property
    def email(self) -> str:
        """Convenience for API schemas: the member's email."""
        return self.user.email

    @property
    def full_name(self) -> str:
        """Convenience for API schemas: the member's display name."""
        return self.user.full_name
