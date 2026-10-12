# What is this file?   API endpoints for the current company and its members.
# Flutter/Dart idea:   the controller. Each function = one route.
# The URL says 'current' - the company is NOT in the URL. It comes from the login
# token, so you cannot type another company's id here.
# Pattern in every handler:  permission check (Depends) -> service call -> response model.
"""HTTP endpoints for the current organization and its members.

Routes are thin on purpose: authenticate/authorize via dependencies, call one
service method, shape the response. No business rules live here.
"""

import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, Response, status

from app.core.pagination import Page, PageParamsDep
from app.modules.auth.deps import DbDep, TenantContext, require_permission
from app.modules.organizations.member_service import MemberService
from app.modules.organizations.schemas import (
    MemberCreate,
    MemberListQuery,
    MemberOut,
    MemberRoleUpdate,
    OrganizationOut,
    OrganizationUpdate,
)
from app.modules.organizations.service import OrganizationService
from app.modules.rbac.constants import Permission

router = APIRouter(prefix="/organizations/current", tags=["organizations"])

# Reusable names for 'this route needs permission X'. The value you get is a TenantContext.
ReadOrgCtx = Annotated[TenantContext, Depends(require_permission(Permission.ORG_READ))]
UpdateOrgCtx = Annotated[TenantContext, Depends(require_permission(Permission.ORG_UPDATE))]
ReadMembersCtx = Annotated[TenantContext, Depends(require_permission(Permission.MEMBERS_READ))]
ManageMembersCtx = Annotated[TenantContext, Depends(require_permission(Permission.MEMBERS_MANAGE))]


# GET /organizations/current
@router.get("", response_model=OrganizationOut)
def get_current_organization(db: DbDep, ctx: ReadOrgCtx) -> OrganizationOut:
    """Return the caller's organization."""
    return OrganizationOut.model_validate(OrganizationService(db, ctx).get_current())


# PATCH /organizations/current - rename.
@router.patch("", response_model=OrganizationOut)
def update_current_organization(
    body: OrganizationUpdate, db: DbDep, ctx: UpdateOrgCtx
) -> OrganizationOut:
    """Rename the caller's organization (owner/admin only)."""
    return OrganizationOut.model_validate(OrganizationService(db, ctx).update_current(body.name))


# GET /organizations/current/members?page=&q=&sort_by=
@router.get("/members", response_model=Page[MemberOut])
def list_members(
    params: PageParamsDep,
    query: Annotated[MemberListQuery, Depends()],
    db: DbDep,
    ctx: ReadMembersCtx,
) -> Page[MemberOut]:
    """List members with pagination, `?q=` search and `?sort_by=&sort_order=` sorting."""
    rows, total = MemberService(db, ctx).list_members(params, query)
    return Page(
        items=[MemberOut.model_validate(r) for r in rows],
        total=total,
        page=params.page,
        page_size=params.page_size,
    )


# POST - add a member. 201 = created.
@router.post("/members", response_model=MemberOut, status_code=status.HTTP_201_CREATED)
def add_member(body: MemberCreate, db: DbDep, ctx: ManageMembersCtx) -> MemberOut:
    """Add a member (owner/admin only)."""
    return MemberOut.model_validate(MemberService(db, ctx).add_member(body))


# PATCH - change role. `{member_id}` in the URL becomes the `member_id` parameter.
@router.patch("/members/{member_id}", response_model=MemberOut)
def change_member_role(
    member_id: uuid.UUID, body: MemberRoleUpdate, db: DbDep, ctx: ManageMembersCtx
) -> MemberOut:
    """Change a member's role (owner/admin only, subject to rank rules)."""
    return MemberOut.model_validate(MemberService(db, ctx).change_role(member_id, body.role))


# DELETE - remove member. 204 = OK, empty body.
@router.delete("/members/{member_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_member(member_id: uuid.UUID, db: DbDep, ctx: ManageMembersCtx) -> Response:
    """Remove a member (owner/admin only, subject to rank rules)."""
    MemberService(db, ctx).remove_member(member_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
