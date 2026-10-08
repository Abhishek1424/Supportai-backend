"""API response schema for audit logs."""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict


class AuditLogOut(BaseModel):
    """One audit entry as returned by the API."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    actor_user_id: uuid.UUID | None
    action: str
    resource_type: str
    resource_id: uuid.UUID | None
    details: dict[str, Any]
    ip_address: str | None
    created_at: datetime
