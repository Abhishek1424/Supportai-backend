"""User model: a person who can log in. A user may belong to several organizations."""

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, IdMixin, TimestampMixin


class User(IdMixin, TimestampMixin, Base):
    """A login identity.

    Not tenant-owned: the same person can be a member of multiple organizations
    (via OrganizationMember), so the user row itself has no organization_id.
    """

    __tablename__ = "users"

    # Always stored lower-case and trimmed (normalised by the schema layer).
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    # Never serialised in any API response; schemas simply do not declare it.
    password_hash: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
