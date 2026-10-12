# What is this file?   Database queries for users. No business rules here.
# Why?                 Keeps SQL in one place. The service calls it.
# Flutter/Dart idea:   a Repository class, like `UserRepository` that wraps a database.
# Flow:                service.py -> UserRepository -> Session -> PostgreSQL
"""Data access for users (global table, so not tenant-scoped)."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.modules.users.models import User


# Repository = only data access. The Session (database connection) is passed in the
#   constructor = dependency injection by constructor.
class UserRepository:
    """Queries on the `users` table. Contains no business rules."""

    def __init__(self, session: Session) -> None:
        """Bind to the request's session."""
        self.session = session

    # Returns a User or None. In Dart: `Future<User?> getByEmail(String email)`, but here it
    #   is not async.
    def get_by_email(self, email: str) -> User | None:
        """Find a user by (already normalised, lower-case) email.

        Used by login and by "add member". Returns None when not found.
        """
        return self.session.scalar(select(User).where(User.email == email))

    # `flush` sends the INSERT to the database now, but does not finish the transaction.
    # So errors (like a duplicate email) show up immediately, and the service can still
    # roll back everything. The commit happens later in the service.
    def add(self, user: User) -> User:
        """Stage a new user for insertion and flush so its id/constraints are checked now.

        Flush (not commit) keeps the surrounding service transaction open
        while still surfacing unique-email violations immediately.
        """
        self.session.add(user)
        self.session.flush()
        return user
