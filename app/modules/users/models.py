# What is this file?   The `users` table, written as a class (an "ORM model").
# Why?                 One row = one person who can log in.
# Flutter/Dart idea:   a Drift/Floor table class, or a Dart data class that matches
#                      one database row. Unlike a JSON model, it is tied to the database.
# Note: a user is NOT tied to one company. One person can join many companies
#       (see OrganizationMember).
"""User model: a person who can log in. A user may belong to several organizations."""

from sqlalchemy import Boolean, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, IdMixin, TimestampMixin


# Each attribute below is a column. `Mapped[str]` is the Dart-like type `String`.
class User(IdMixin, TimestampMixin, Base):
    """A login identity.

    Not tenant-owned: the same person can be a member of multiple organizations
    (via OrganizationMember), so the user row itself has no organization_id.
    """

    __tablename__ = "users"

    # Always stored lower-case and trimmed (normalised by the schema layer).
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    # Never serialised in any API response; schemas simply do not declare it.
    # We save only the hash of the password, never the real password. Schemas never return
    #   this field.
    password_hash: Mapped[str] = mapped_column(String(255))
    full_name: Mapped[str] = mapped_column(String(200))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
