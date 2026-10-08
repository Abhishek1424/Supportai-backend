"""Centralized, structured error handling.

Responsibility: define the application's error types and turn ANY exception
into the same JSON shape:

    {"error": {"code": "CONVERSATION_NOT_FOUND", "message": "...", "request_id": "..."}}

Why: clients (web, mobile, widget) can switch on the stable `code` string
instead of parsing messages, and no stack trace or internal detail ever
reaches a user. Services raise `AppError` subclasses; they never build HTTP
responses themselves.
"""

from enum import StrEnum
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette import status
from starlette.exceptions import HTTPException as StarletteHTTPException

log = structlog.get_logger()


class ErrorCode(StrEnum):
    """Every machine-readable error code the API can return.

    Kept in one enum so there are no magic strings and the full list is
    visible to frontend developers.
    """

    VALIDATION_ERROR = "VALIDATION_ERROR"
    INTERNAL_ERROR = "INTERNAL_ERROR"
    HTTP_ERROR = "HTTP_ERROR"
    RATE_LIMITED = "RATE_LIMITED"
    NOT_AUTHENTICATED = "NOT_AUTHENTICATED"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    INVALID_TOKEN = "INVALID_TOKEN"
    REFRESH_TOKEN_REUSED = "REFRESH_TOKEN_REUSED"
    PERMISSION_DENIED = "PERMISSION_DENIED"
    NO_ACTIVE_ORGANIZATION = "NO_ACTIVE_ORGANIZATION"
    ORGANIZATION_SUSPENDED = "ORGANIZATION_SUSPENDED"
    EMAIL_ALREADY_REGISTERED = "EMAIL_ALREADY_REGISTERED"
    ORGANIZATION_NOT_FOUND = "ORGANIZATION_NOT_FOUND"
    MEMBER_NOT_FOUND = "MEMBER_NOT_FOUND"
    MEMBER_ALREADY_EXISTS = "MEMBER_ALREADY_EXISTS"
    NEW_USER_DETAILS_REQUIRED = "NEW_USER_DETAILS_REQUIRED"
    CANNOT_MANAGE_ROLE = "CANNOT_MANAGE_ROLE"
    LAST_OWNER = "LAST_OWNER"


class AppError(Exception):
    """Base class for all expected (business) errors.

    Subclass it for each HTTP category; raise it from services. The exception
    handler below converts it into the standard JSON body.
    """

    status_code: int = status.HTTP_400_BAD_REQUEST

    def __init__(self, code: ErrorCode, message: str, *, headers: dict[str, str] | None = None):
        """Create an error.

        Args:
            code: stable machine-readable identifier.
            message: safe, human-readable text (never include secrets or internals).
            headers: optional HTTP headers, e.g. Retry-After.
        """
        super().__init__(message)
        self.code = code
        self.message = message
        self.headers = headers


class BadRequestError(AppError):
    """The request is understood but violates a business rule (HTTP 400)."""

    status_code = status.HTTP_400_BAD_REQUEST


class UnauthorizedError(AppError):
    """The caller is not authenticated or their credentials are invalid (HTTP 401)."""

    status_code = status.HTTP_401_UNAUTHORIZED


class ForbiddenError(AppError):
    """The caller is authenticated but not allowed to do this (HTTP 403)."""

    status_code = status.HTTP_403_FORBIDDEN


class NotFoundError(AppError):
    """The resource does not exist OR belongs to another tenant (HTTP 404).

    Important: cross-tenant access deliberately returns 404, not 403, so an
    attacker cannot learn which IDs exist in other organizations.
    """

    status_code = status.HTTP_404_NOT_FOUND


class ConflictError(AppError):
    """The request conflicts with current state, e.g. duplicate email (HTTP 409)."""

    status_code = status.HTTP_409_CONFLICT


class RateLimitedError(AppError):
    """Too many requests from this caller (HTTP 429)."""

    status_code = status.HTTP_429_TOO_MANY_REQUESTS


def _error_body(request: Request, code: str, message: str, details: Any = None) -> dict[str, Any]:
    """Build the standard error JSON body.

    Args:
        request: used to read the request_id set by the request-context middleware.
        code: machine-readable error code.
        message: human-readable message.
        details: optional extra data (used for field-level validation errors).
    Returns:
        A dict ready to be serialized as the response body.
    """
    error: dict[str, Any] = {
        "code": code,
        "message": message,
        "request_id": getattr(request.state, "request_id", None),
    }
    if details is not None:
        error["details"] = details
    return {"error": error}


async def _handle_app_error(request: Request, exc: Exception) -> JSONResponse:
    """Convert an expected AppError into the standard response.

    Logged at info level: these are normal outcomes (wrong password, not found),
    not bugs, so they must not page anyone.
    """
    assert isinstance(exc, AppError)
    log.info("app_error", error_code=exc.code, status_code=exc.status_code)
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_body(request, exc.code, exc.message),
        headers=exc.headers,
    )


async def _handle_validation_error(request: Request, exc: Exception) -> JSONResponse:
    """Convert Pydantic request-validation failures into HTTP 422.

    Only the field location and message are returned. The raw input is stripped
    because it could contain a password the user just typed.
    """
    assert isinstance(exc, RequestValidationError)
    details = [
        {"field": ".".join(str(p) for p in e["loc"]), "message": e["msg"]} for e in exc.errors()
    ]
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
        content=_error_body(
            request, ErrorCode.VALIDATION_ERROR, "Request validation failed.", details
        ),
    )


async def _handle_http_exception(request: Request, exc: Exception) -> JSONResponse:
    """Convert framework-level HTTP errors (404 unknown route, 405, ...) to our shape."""
    assert isinstance(exc, StarletteHTTPException)
    return JSONResponse(
        status_code=exc.status_code,
        content=_error_body(request, ErrorCode.HTTP_ERROR, str(exc.detail)),
        headers=getattr(exc, "headers", None),
    )


async def _handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
    """Last line of defense for bugs.

    The full traceback goes to the logs; the user sees only a generic message
    plus the request_id they can quote to support.
    """
    log.error("unhandled_exception", exc_info=exc)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=_error_body(request, ErrorCode.INTERNAL_ERROR, "An unexpected error occurred."),
    )


def register_exception_handlers(app: FastAPI) -> None:
    """Attach all handlers to the FastAPI app (called once from main.py)."""
    app.add_exception_handler(AppError, _handle_app_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
    app.add_exception_handler(StarletteHTTPException, _handle_http_exception)
    app.add_exception_handler(Exception, _handle_unexpected_error)
