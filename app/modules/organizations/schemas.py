"""Request/response schemas for organizations and members."""

import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from app.modules.rbac.constants import Role

PASSWORD_MIN_LENGTH = 10
PASSWORD_MAX_LENGTH = 128  # Upper bound prevents huge inputs from burning CPU in argon2.


class OrganizationOut(BaseModel):
    """Organization as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    created_at: datetime


class OrganizationUpdate(BaseModel):
    """Fields an admin may change on their organization."""

    name: str = Field(min_length=1, max_length=200)

    @field_validator("name")
    @classmethod
    def strip_name(cls, value: str) -> str:
        """Trim whitespace; reject names that are only spaces."""
        value = value.strip()
        if not value:
            raise ValueError("name must not be blank")
        return value


class MemberOut(BaseModel):
    """A member of the organization. Note: no password hash, by construction."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    email: str
    full_name: str
    role: Role
    created_at: datetime


class MemberCreate(BaseModel):
    """Add a person to the organization.

    If the email already belongs to a registered user they are simply added.
    Otherwise `full_name` and `password` are required to create their account
    (an email-invitation flow replaces this once email delivery exists).
    """

    email: EmailStr
    role: Role
    full_name: str | None = Field(default=None, min_length=1, max_length=200)
    password: str | None = Field(
        default=None, min_length=PASSWORD_MIN_LENGTH, max_length=PASSWORD_MAX_LENGTH
    )

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value: str) -> str:
        """Lower-case so 'A@x.com' and 'a@x.com' are the same account."""
        return value.strip().lower()


class MemberRoleUpdate(BaseModel):
    """Change a member's role."""

    role: Role


class MemberListQuery(BaseModel):
    """Search/sort options for the member list."""

    q: str | None = None
    sort_by: Literal["created_at", "email", "full_name", "role"] = "created_at"
    sort_order: Literal["asc", "desc"] = "asc"
