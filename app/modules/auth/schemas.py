"""Request/response schemas for authentication."""

import uuid

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.modules.organizations.schemas import (
    PASSWORD_MAX_LENGTH,
    PASSWORD_MIN_LENGTH,
    OrganizationOut,
)
from app.modules.rbac.constants import Permission, Role


def _normalise_email(value: str) -> str:
    """Trim + lower-case emails so lookups are case-insensitive."""
    return value.strip().lower()


class RegisterRequest(BaseModel):
    """Sign up a new business: creates the user AND their organization."""

    email: EmailStr
    password: str = Field(min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH)
    full_name: str = Field(min_length=1, max_length=200)
    organization_name: str = Field(min_length=1, max_length=200)

    _email = field_validator("email")(_normalise_email)


class LoginRequest(BaseModel):
    """Email + password. `organization_id` picks the workspace for multi-org users."""

    email: EmailStr
    # max_length stops absurdly long inputs from being fed to the password hasher.
    password: str = Field(min_length=1, max_length=PASSWORD_MAX_LENGTH)
    organization_id: uuid.UUID | None = None

    _email = field_validator("email")(_normalise_email)


class RefreshRequest(BaseModel):
    """Body for /auth/refresh and /auth/logout."""

    refresh_token: str = Field(min_length=1, max_length=512)


class TokenPair(BaseModel):
    """Credentials returned after register/login/refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # access-token lifetime in seconds


class UserOut(BaseModel):
    """The logged-in user. Never includes the password hash."""

    id: uuid.UUID
    email: str
    full_name: str


class MeOut(BaseModel):
    """Who am I, where, and what may I do (used by frontends to render the UI)."""

    user: UserOut
    organization: OrganizationOut
    role: Role
    permissions: list[Permission]
