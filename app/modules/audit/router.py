# What is this file?   The API endpoint for viewing the audit log: GET /api/v1/audit-logs
# Flutter/Dart idea:   the "controller" / handler for one route.
# Flow:  request -> check login + permission -> AuditService.search -> JSON page.
"""HTTP endpoints for viewing the audit log."""

import uuid
from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends

from app.core.pagination import Page, PageParamsDep
from app.modules.audit.schemas import AuditLogOut
from app.modules.audit.service import AuditService
from app.modules.auth.deps import DbDep, TenantContext, require_permission
from app.modules.rbac.constants import Permission

# A group of routes with a shared URL prefix. Dart idea: a nested route group.
router = APIRouter(prefix="/audit-logs", tags=["audit"])

# `Depends(...)` = dependency injection. Before the function runs, FastAPI runs
# `require_permission(AUDIT_READ)`. If the user is not allowed, the function never runs.
# The result is a TenantContext (who is calling, which company, which role).
# `Annotated[X, Depends(f)]` just saves a reusable name.
AuditReadCtx = Annotated[TenantContext, Depends(require_permission(Permission.AUDIT_READ))]


# Decorator = register this function as GET /audit-logs.
# `response_model` = the shape of the JSON that will be returned.
# Function parameters like `action: str | None` become URL query params (?action=...).
@router.get("", response_model=Page[AuditLogOut])
def list_audit_logs(
    params: PageParamsDep,
    db: DbDep,
    ctx: AuditReadCtx,
    action: str | None = None,
    actor_user_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
) -> Page[AuditLogOut]:
    """List the caller's organization's audit entries, newest first.

    Flow: auth dependency verifies the token and the `audit:read` permission ->
    the AuditService (bound to ctx.organization_id) queries -> response.
    Only entries of the caller's own tenant can ever be returned.
    """
    rows, total = AuditService(db, ctx.organization_id).search(
        params,
        action=action,
        actor_user_id=actor_user_id,
        resource_type=resource_type,
        created_from=created_from,
        created_to=created_to,
    )
    return Page(
        items=[AuditLogOut.model_validate(r) for r in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )
