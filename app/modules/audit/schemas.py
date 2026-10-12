# What is this file?   JSON shape of an audit entry in the API response.
# Flutter/Dart idea:   a response model class with toJson. `from_attributes=True`
#                      means: build it directly from a database object.
# Models (models.py) = database rows.  Schemas (schemas.py) = JSON sent to the app.
# They are separate on purpose, so secret columns are never sent by accident.
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
