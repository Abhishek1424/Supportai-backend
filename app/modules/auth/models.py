# What is this file?   The `refresh_tokens` table.
# Why?                 We save a hash of each refresh token so we can check it,
#                      rotate it, and revoke it (logout / theft).
# Idea: "family" = all tokens from ONE login. Each refresh makes a new token in the
#       same family. If an OLD token is used again, someone may have stolen it,
#       so the whole family is revoked.
"""Refresh-token storage."""

import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, IdMixin, TenantMixin, TimestampMixin


class RefreshToken(IdMixin, TimestampMixin, TenantMixin, Base):
    """One issued refresh token (only its hash is stored).

    Tokens form a "family": every rotation creates a new row with the same
    `family_id`. If an already-used token is presented again (a sign of theft),
    the whole family is revoked.
    """

    __tablename__ = "refresh_tokens"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    family_id: Mapped[uuid.UUID] = mapped_column(index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), default=None)
