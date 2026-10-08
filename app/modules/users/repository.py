"""Data access for users (global table, so not tenant-scoped)."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.modules.users.models import User


class UserRepository:
    """Queries on the `users` table. Contains no business rules."""

    def __init__(self, session: Session) -> None:
        """Bind to the request's session."""
        self.session = session

    def get_by_email(self, email: str) -> User | None:
        """Find a user by (already normalised, lower-case) email.

        Used by login and by "add member". Returns None when not found.
        """
        return self.session.scalar(select(User).where(User.email == email))

    def add(self, user: User) -> User:
        """Stage a new user for insertion and flush so its id/constraints are checked now.

        Flush (not commit) keeps the surrounding service transaction open
        while still surfacing unique-email violations immediately.
        """
        self.session.add(user)
        self.session.flush()
        return user
