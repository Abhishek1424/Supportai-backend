# What is this file?   The auth API endpoints: register, login, refresh, logout, me.
# Flutter/Dart idea:   the controller layer. Each function is one route handler.
# Rule:                handlers stay tiny: validate -> call the service -> return.
# Flow:  Flutter/web app -> POST /api/v1/auth/login -> login() -> AuthService.login()
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

# Shortcut for 'give me the rate limiter'. Same Depends idea as before.
LimiterDep = Annotated[RateLimiter, Depends(get_rate_limiter)]


# A dependency that BUILDS the AuthService for each request. This is dependency
# injection: it receives the database session and the limiter, and passes them
# into the service constructor. Dart idea: a Provider that creates AuthService.
def _service(request: Request, db: DbDep, limiter: LimiterDep) -> AuthService:
    """Build an AuthService for this request (dependency injection point)."""
    return AuthService(db, limiter, request.client.host if request.client else None)


ServiceDep = Annotated[AuthService, Depends(_service)]


# Decorator: POST /api/v1/auth/register. 201 = Created.
@router.post("/register", response_model=TokenPair, status_code=status.HTTP_201_CREATED)
def register(body: RegisterRequest, service: ServiceDep) -> TokenPair:
    """Create a new organization and its owner account."""
    return service.register(body)


# POST /api/v1/auth/login. Returns TokenPair (typed by response_model).
@router.post("/login", response_model=TokenPair)
def login(body: LoginRequest, service: ServiceDep) -> TokenPair:
    """Log in with email and password."""
    return service.login(body)


# POST /api/v1/auth/refresh.
@router.post("/refresh", response_model=TokenPair)
def refresh(body: RefreshRequest, service: ServiceDep) -> TokenPair:
    """Rotate the refresh token and get a new access token."""
    return service.refresh(body.refresh_token)


# POST /api/v1/auth/logout. 204 = success with no body.
@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(body: RefreshRequest, service: ServiceDep) -> Response:
    """End the session by revoking its refresh token."""
    service.logout(body.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# GET /api/v1/auth/me. Needs a valid token. Returns user + company + role + permissions.
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
