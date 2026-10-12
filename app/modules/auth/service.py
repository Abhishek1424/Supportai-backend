# What is this file?   The business logic of authentication.
# Why?                 Routers stay thin. All rules live here: register, login,
#                      refresh (token rotation), logout.
# Flutter/Dart idea:   an `AuthService` class. Your Flutter AuthService calls the API;
#                      this one IS the API side. It uses repositories (data) and security
#                        helpers.
# Flow of login:  router -> AuthService.login -> UserRepository -> verify password
#                 -> create tokens -> audit -> commit -> TokenPair.
"""Authentication business logic: register, login, refresh (rotation), logout."""

import uuid
from datetime import timedelta

import structlog
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.errors import (
    ConflictError,
    ErrorCode,
    ForbiddenError,
    UnauthorizedError,
)
from app.core.rate_limit import RateLimiter, enforce_rate_limit
from app.core.security import (
    DUMMY_PASSWORD_HASH,
    create_access_token,
    generate_refresh_token,
    hash_password,
    hash_refresh_token,
    verify_password,
)
from app.db.base import utcnow
from app.modules.audit.constants import AuditAction
from app.modules.audit.service import AuditService
from app.modules.auth.models import RefreshToken
from app.modules.auth.repository import RefreshTokenRepository
from app.modules.auth.schemas import LoginRequest, RegisterRequest, TokenPair
from app.modules.organizations.models import OrganizationMember
from app.modules.organizations.repository import OrganizationRepository
from app.modules.organizations.service import create_organization
from app.modules.rbac.constants import Role
from app.modules.users.models import User
from app.modules.users.repository import UserRepository

# A logger. Dart idea: `final log = Logger();`.
log = structlog.get_logger()


# Gets its helpers through the constructor (dependency injection).
class AuthService:
    """Everything about proving identity and issuing tokens."""

    def __init__(self, session: Session, limiter: RateLimiter, ip_address: str | None) -> None:
        """Bind to the request session, a rate limiter and the caller's IP.

        Args:
            session: request DB session.
            limiter: backend used to throttle brute-force attempts.
            ip_address: caller IP (rate-limit key + audit trail).
        """
        self.session = session
        self.limiter = limiter
        self.ip = ip_address or "unknown"
        self.users = UserRepository(session)
        self.orgs = OrganizationRepository(session)
        self.tokens = RefreshTokenRepository(session)

    # Creates a company + its owner user and logs them in, all in ONE transaction.
    # Dart idea: like running several database writes inside one `db.transaction(...)`.
    # If the same email registers twice at the same time, the database unique index
    # stops the second one and we return a friendly 409.
    def register(self, data: RegisterRequest) -> TokenPair:
        """Create a new user + organization and log them in.

        Flow:
        1. Throttle by IP.
        2. Reject an already-registered email.
        3. Create organization -> user -> OWNER membership.
        4. Audit "organization.created".
        5. Issue tokens and commit everything in ONE transaction.

        Raises:
            RateLimitedError, ConflictError(EMAIL_ALREADY_REGISTERED).
        Edge case: two simultaneous sign-ups with the same email -> the unique
        index rejects the second; we translate that into the same ConflictError.
        """
        enforce_rate_limit(self.limiter, f"register:ip:{self.ip}")
        if self.users.get_by_email(data.email) is not None:
            raise ConflictError(ErrorCode.EMAIL_ALREADY_REGISTERED, "Email is already registered.")

        try:
            organization = create_organization(self.session, data.organization_name.strip())
            user = self.users.add(
                User(
                    email=data.email,
                    full_name=data.full_name.strip(),
                    password_hash=hash_password(data.password),
                )
            )
        except IntegrityError as exc:
            self.session.rollback()
            raise ConflictError(
                ErrorCode.EMAIL_ALREADY_REGISTERED, "Email is already registered."
            ) from exc

        self.session.add(
            OrganizationMember(organization_id=organization.id, user_id=user.id, role=Role.OWNER)
        )
        AuditService(self.session, organization.id).record(
            AuditAction.ORG_CREATED,
            actor_user_id=user.id,
            resource_type="organization",
            resource_id=organization.id,
            ip_address=self.ip,
        )
        pair = self._issue_tokens(user.id, organization.id, family_id=uuid.uuid4())
        self.session.commit()
        return pair

    # Check password -> pick the company -> make tokens -> write audit -> commit.
    # Wrong email and wrong password give the SAME error on purpose (no information leak).
    # Rate limit is checked first (by IP and by email).
    def login(self, data: LoginRequest) -> TokenPair:
        """Verify email + password and issue tokens for one organization.

        Flow:
        1. Throttle by IP and by email.
        2. Look up the user; verify the password. If the user does not exist we
           still verify against a dummy hash so timing does not reveal it.
        3. Choose the organization (requested one, or the user's oldest).
        4. Issue tokens, audit, commit.

        Raises:
            RateLimitedError.
            UnauthorizedError(INVALID_CREDENTIALS): wrong email OR password OR disabled
                account - deliberately the same message for all three.
            ForbiddenError: no active organization / not a member of the requested one.
        """
        enforce_rate_limit(self.limiter, f"login:ip:{self.ip}")
        enforce_rate_limit(self.limiter, f"login:email:{data.email}")

        user = self.users.get_by_email(data.email)
        password_ok = verify_password(
            data.password, user.password_hash if user else DUMMY_PASSWORD_HASH
        )
        if user is None or not password_ok or not user.is_active:
            log.info("login_failed", reason="invalid_credentials")
            raise UnauthorizedError(ErrorCode.INVALID_CREDENTIALS, "Invalid email or password.")

        memberships = [
            m for m in self.orgs.list_memberships_for_user(user.id) if m.organization.is_active
        ]
        if data.organization_id is not None:
            memberships = [m for m in memberships if m.organization_id == data.organization_id]
        if not memberships:
            raise ForbiddenError(
                ErrorCode.NO_ACTIVE_ORGANIZATION,
                "No active organization available for this account.",
            )
        organization_id = memberships[0].organization_id

        pair = self._issue_tokens(user.id, organization_id, family_id=uuid.uuid4())
        AuditService(self.session, organization_id).record(
            AuditAction.LOGIN_SUCCEEDED,
            actor_user_id=user.id,
            resource_type="user",
            resource_id=user.id,
            ip_address=self.ip,
        )
        self.session.commit()
        return pair

    # Swap an old refresh token for a new pair (ROTATION).
    # If an already-used token comes again -> possible theft -> revoke the whole family.
    # Flutter idea: this is what your Dio interceptor calls when it gets a 401.
    def refresh(self, raw_token: str) -> TokenPair:
        """Exchange a refresh token for a new access + refresh pair (rotation).

        Flow:
        1. Look up the token by hash.
        2. If it was ALREADY used (revoked) -> someone replayed it: revoke the
           whole family, audit, and force a fresh login.
        3. Check expiry and that the user/membership/organization are still valid.
        4. Revoke the presented token and issue a new one in the same family.

        Raises:
            UnauthorizedError: INVALID_TOKEN, or REFRESH_TOKEN_REUSED on replay.
        """
        enforce_rate_limit(self.limiter, f"refresh:ip:{self.ip}")
        now = utcnow()
        stored = self.tokens.get_by_hash(hash_refresh_token(raw_token))
        if stored is None:
            raise UnauthorizedError(ErrorCode.INVALID_TOKEN, "Invalid refresh token.")

        if stored.revoked_at is not None:
            # Commit the revocation BEFORE raising, otherwise the rollback would undo it.
            self.tokens.revoke_family(stored.family_id, now)
            AuditService(self.session, stored.organization_id).record(
                AuditAction.TOKEN_REUSE_DETECTED,
                actor_user_id=stored.user_id,
                resource_type="user",
                resource_id=stored.user_id,
                ip_address=self.ip,
            )
            self.session.commit()
            raise UnauthorizedError(
                ErrorCode.REFRESH_TOKEN_REUSED,
                "Refresh token was already used. Please log in again.",
            )

        membership = self.orgs.get_membership(stored.user_id, stored.organization_id)
        if (
            stored.expires_at <= now
            or membership is None
            or not membership.user.is_active
            or not membership.organization.is_active
        ):
            raise UnauthorizedError(ErrorCode.INVALID_TOKEN, "Invalid refresh token.")

        stored.revoked_at = now
        pair = self._issue_tokens(
            stored.user_id, stored.organization_id, family_id=stored.family_id
        )
        self.session.commit()
        return pair

    # Revokes the refresh token family. Safe to call twice; unknown tokens are ignored.
    def logout(self, raw_token: str) -> None:
        """Revoke the refresh-token family so the session cannot be renewed.

        Idempotent and silent for unknown tokens: the caller learns nothing
        about which tokens exist. The short-lived access token simply expires.
        """
        stored = self.tokens.get_by_hash(hash_refresh_token(raw_token))
        if stored is not None:
            self.tokens.revoke_family(stored.family_id, utcnow())
            self.session.commit()

    # Private helper (starts with `_`). Makes the JWT and saves the refresh-token HASH.
    # Returns the real refresh token only here; the database never sees it.
    def _issue_tokens(
        self, user_id: uuid.UUID, organization_id: uuid.UUID, family_id: uuid.UUID
    ) -> TokenPair:
        """Create an access JWT and persist a new refresh token (hash only).

        Does not commit; the caller's transaction decides.

        Args:
            user_id / organization_id: identity the tokens represent.
            family_id: the rotation chain this refresh token belongs to.
        Returns:
            The TokenPair to hand to the client. The raw refresh token exists
            only in this return value; the database stores just its hash.
        """
        settings = get_settings()
        raw_refresh = generate_refresh_token()
        self.tokens.add(
            RefreshToken(
                organization_id=organization_id,
                user_id=user_id,
                family_id=family_id,
                token_hash=hash_refresh_token(raw_refresh),
                expires_at=utcnow() + timedelta(days=settings.refresh_token_ttl_days),
            )
        )
        return TokenPair(
            access_token=create_access_token(user_id, organization_id),
            refresh_token=raw_refresh,
            expires_in=settings.access_token_ttl_minutes * 60,
        )
