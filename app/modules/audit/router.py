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

router = APIRouter(prefix="/audit-logs", tags=["audit"])

AuditReadCtx = Annotated[TenantContext, Depends(require_permission(Permission.AUDIT_READ))]


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
