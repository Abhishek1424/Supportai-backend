# Unit tests for passwords and tokens. No database. Includes attack cases: tampered token,
#   expired token, 'alg: none'.
"""Unit tests for password hashing and token handling (no database, no HTTP)."""

import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest

from app.core.config import get_settings
from app.core.errors import UnauthorizedError
from app.core.security import (
    JWT_ALGORITHM,
    create_access_token,
    decode_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)


def test_password_hash_verifies_and_is_salted() -> None:
    first, second = hash_password("s3cret-password"), hash_password("s3cret-password")
    assert first != second  # random salt per hash
    assert verify_password("s3cret-password", first)
    assert not verify_password("wrong", first)


def test_verify_password_returns_false_for_garbage_hash() -> None:
    assert verify_password("anything", "not-a-hash") is False


def test_access_token_round_trip() -> None:
    user_id, org_id = uuid.uuid4(), uuid.uuid4()
    claims = decode_access_token(create_access_token(user_id, org_id))
    assert (claims.user_id, claims.organization_id) == (user_id, org_id)


def test_tampered_token_is_rejected() -> None:
    token = create_access_token(uuid.uuid4(), uuid.uuid4())
    with pytest.raises(UnauthorizedError):
        decode_access_token(token[:-2] + "xx")


def test_expired_token_is_rejected() -> None:
    key = get_settings().secret_key.get_secret_value()
    expired = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "org": str(uuid.uuid4()),
            "typ": "access",
            "exp": datetime.now(UTC) - timedelta(seconds=1),
        },
        key,
        algorithm=JWT_ALGORITHM,
    )
    with pytest.raises(UnauthorizedError):
        decode_access_token(expired)


def test_token_with_wrong_type_is_rejected() -> None:
    key = get_settings().secret_key.get_secret_value()
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "org": str(uuid.uuid4()),
            "typ": "refresh",
            "exp": datetime.now(UTC) + timedelta(minutes=5),
        },
        key,
        algorithm=JWT_ALGORITHM,
    )
    with pytest.raises(UnauthorizedError):
        decode_access_token(token)


def test_unsigned_token_is_rejected() -> None:
    """The classic 'alg: none' attack must not work."""
    forged = jwt.encode(
        {"sub": str(uuid.uuid4()), "org": str(uuid.uuid4()), "typ": "access"},
        None,
        algorithm="none",
    )
    with pytest.raises(UnauthorizedError):
        decode_access_token(forged)


def test_refresh_tokens_are_unique_and_hash_is_deterministic() -> None:
    a, b = generate_refresh_token(), generate_refresh_token()
    assert a != b
    assert hash_refresh_token(a) == hash_refresh_token(a)
    assert hash_refresh_token(a) != a  # raw token is never what we store
