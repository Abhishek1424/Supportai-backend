"""Cryptographic primitives: password hashing, access JWTs, refresh tokens.

Responsibility: the ONLY place that touches passwords, signing keys and token
generation. Services call these functions; they never use argon2/jwt directly.

Design:
- Passwords: argon2id (memory-hard, the current OWASP recommendation).
- Access token: short-lived signed JWT. It only proves WHO the user is and
  WHICH organization they act in. Role/permissions are re-read from the
  database on each request so a removed member loses access immediately.
- Refresh token: random opaque string. Only its SHA-256 hash is stored, so a
  database leak does not leak usable tokens.
"""

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

from app.core.config import get_settings
from app.core.errors import ErrorCode, UnauthorizedError

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_TYPE = "access"
REFRESH_TOKEN_BYTES = 48  # 384 bits of randomness

_hasher = PasswordHasher()

# A real hash of a throwaway password. Login verifies against it when the email
# is unknown so "unknown email" and "wrong password" take the same time
# (prevents user enumeration through response-time differences).
DUMMY_PASSWORD_HASH = _hasher.hash("not-a-real-password")


@dataclass(frozen=True)
class AccessTokenClaims:
    """The verified contents of an access token."""

    user_id: uuid.UUID
    organization_id: uuid.UUID


def hash_password(password: str) -> str:
    """Hash a plaintext password for storage.

    Args:
        password: the plaintext password (validated for length by the schema layer).
    Returns:
        An argon2id hash string containing its own salt and parameters.
    """
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Check a plaintext password against a stored hash.

    Args:
        password: plaintext supplied by the user.
        password_hash: the stored argon2 hash.
    Returns:
        True on match; False on mismatch OR if the stored hash is malformed
        (a corrupt hash must never crash login or grant access).
    """
    try:
        return _hasher.verify(password_hash, password)
    except (VerificationError, InvalidHashError):
        return False


def create_access_token(user_id: uuid.UUID, organization_id: uuid.UUID) -> str:
    """Issue a signed access JWT.

    Args:
        user_id: the authenticated user.
        organization_id: the tenant this token acts within.
    Returns:
        The encoded JWT string.
    Important:
        Claims are deliberately minimal (no role, no email). Anything that can
        change after issuing belongs in the database, not in the token.
    """
    settings = get_settings()
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "org": str(organization_id),
        "typ": ACCESS_TOKEN_TYPE,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_ttl_minutes),
    }
    return jwt.encode(payload, settings.secret_key.get_secret_value(), algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> AccessTokenClaims:
    """Verify an access JWT and return its claims.

    Args:
        token: the raw bearer token from the Authorization header.
    Returns:
        The verified claims.
    Raises:
        UnauthorizedError: if the token is expired, tampered, malformed, or not an access token.
    Edge cases:
        The algorithm list is pinned to HS256 so an attacker cannot downgrade
        to "none"; `exp`/`sub`/`org` are required.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token,
            settings.secret_key.get_secret_value(),
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "sub", "org", "typ"]},
        )
        if payload["typ"] != ACCESS_TOKEN_TYPE:
            raise jwt.InvalidTokenError("wrong token type")
        return AccessTokenClaims(
            user_id=uuid.UUID(payload["sub"]), organization_id=uuid.UUID(payload["org"])
        )
    except (jwt.InvalidTokenError, ValueError) as exc:
        raise UnauthorizedError(
            ErrorCode.INVALID_TOKEN, "Invalid or expired access token."
        ) from exc


def generate_refresh_token() -> str:
    """Create a new random refresh token (returned to the client exactly once)."""
    return secrets.token_urlsafe(REFRESH_TOKEN_BYTES)


def hash_refresh_token(token: str) -> str:
    """Hash a refresh token for storage/lookup.

    Why SHA-256 and not argon2: the token already has 384 bits of entropy, so
    it cannot be brute-forced, and we need a fast deterministic hash to look
    the row up by value.
    """
    return hashlib.sha256(token.encode()).hexdigest()
