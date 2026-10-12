# What is this file?   Queries for refresh tokens.
# Note:                Not tenant-scoped, because we look a token up by its secret
#                      hash BEFORE we know who the caller is.
"""Data access for refresh tokens.

Not a TenantRepository: tokens are looked up by their hash BEFORE we know who
the caller is. Safe because the hash is a 384-bit secret only the holder knows.
"""

import uuid
from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.modules.auth.models import RefreshToken


# Plain repository class. The Session comes in through the constructor.
class RefreshTokenRepository:
    """Queries on `refresh_tokens`."""

    def __init__(self, session: Session) -> None:
        """Bind to the request's session."""
        self.session = session

    def add(self, token: RefreshToken) -> None:
        """Stage a new token row."""
        self.session.add(token)

    def get_by_hash(self, token_hash: str) -> RefreshToken | None:
        """Find a token row by the SHA-256 of the presented token."""
        return self.session.scalar(
            select(RefreshToken).where(RefreshToken.token_hash == token_hash)
        )

    # Marks all active tokens of one login as revoked, in one UPDATE.
    def revoke_family(self, family_id: uuid.UUID, now: datetime) -> None:
        """Revoke every still-active token of a family (theft response / logout)."""
        self.session.execute(
            update(RefreshToken)
            .where(RefreshToken.family_id == family_id, RefreshToken.revoked_at.is_(None))
            .values(revoked_at=now)
        )
