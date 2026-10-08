"""HTTP endpoints for authentication.

Tokens are returned in the JSON body (not cookies) because both the web app
and the React Native app use `Authorization: Bearer`. Bearer tokens are not
sent automatically by browsers, so classic CSRF does not apply to this API.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status

from app.core.rate_limit import RateLimiter, get_rate_limiter
from app.modules.auth.deps import DbDep, TenantContext, get_current_context
from app.modules.auth.schemas import (
    LoginRequest,
    MeOut,
    RefreshRequest,
    RegisterRequest,
    TokenPair,
    UserOut,
)
from app.modules.auth.service import AuthService
from app.modules.organizations.schemas import OrganizationOut
from app.modules.organizations.service import OrganizationService

router = APIRouter(prefix="/auth", tags=["auth"])

LimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]


def _service(request: Request, db: DbDep, limiter: LimiterDep) -> AuthService:
    """Build an AuthService for this request (dependency injection point)."""
    return AuthService(db, limiter, request.client.host if request.client else None)


ServiceDep = Annotated[AuthService, Depends(_service)]


@router.post("/register", response_model=TokenPair, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, service: ServiceDep) -> TokenPair:
    """Create a new organization and its owner account."""
    return service.register(body)


@router.post("/login", response_model=TokenPair)
def login(body: LoginRequest, service: ServiceDep) -> TokenPair:
    """Log in with email and password."""
    return service.login(body)


@router.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshRequest, service: ServiceDep) -> TokenPair:
    """Rotate the refresh token and get a new access token."""
    return service.refresh(body.refresh_token)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: RefreshRequest, service: ServiceDep) -> Response:
    """End the session by revoking its refresh token."""
    service.logout(body.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/me", response_model=MeOut)
def me(db: DbDep, ctx: Annotated[TenantContext, Depends(get_current_context)]) -> MeOut:
    """Describe the caller: user, organization, role and permissions."""
    organization = OrganizationService(db, ctx).get_current()
    return MeOut(
        user=UserOut(id=ctx.user.id, email=ctx.user.email, full_name=ctx.user.full_name),
        organization=OrganizationOut.model_validate(organization),
        role=ctx.role,
        permissions=sorted(ctx.permissions),
    )
