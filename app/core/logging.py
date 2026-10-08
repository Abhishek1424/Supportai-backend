"""Structured logging setup and the request-context middleware.

Responsibility: emit logs as key/value events (JSON in production) and make
sure every log line produced during a request carries the same `request_id`.

Why structured: `{"event": "login_failed", "request_id": "..", "error_code": ".."}`
can be filtered and aggregated by log tools; free-text lines cannot.

Security rule: never pass passwords, tokens or API keys to a logger.
"""

import logging
import time
import uuid

import structlog
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

REQUEST_ID_HEADER = "X-Request-ID"


def configure_logging(app_env: str) -> None:
    """Configure structlog + stdlib logging once at startup.

    Args:
        app_env: "production" gets JSON output (machine-readable); anything else
            gets colourful console output (developer-friendly).
    """
    renderer = (
        structlog.processors.JSONRenderer()
        if app_env == "production"
        else structlog.dev.ConsoleRenderer()
    )
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,  # adds request_id bound by the middleware
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.format_exc_info,
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
    )


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Assigns a request_id to every request and logs one summary line per request."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Wrap a request with an id, timing and a completion log.

        Flow:
        1. Reuse the caller's X-Request-ID if present (lets a gateway correlate
           logs), otherwise generate one.
        2. Bind it to structlog's context so every log line includes it, and to
           `request.state` so the error handlers can put it in error bodies.
        3. Run the request, then log method/path/status/duration together with
           user_id and organization_id (set on request.state by the auth
           dependency, so they are only present for authenticated calls).
        4. Echo the id back in the response header.

        Important: the client-supplied id is length-limited to stop log
        injection via a huge or multi-line header.
        """
        request_id = request.headers.get(REQUEST_ID_HEADER, "")[:64] or uuid.uuid4().hex
        request.state.request_id = request_id
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=request_id)

        started = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - started) * 1000, 1)

        structlog.get_logger().info(
            "request_completed",
            method=request.method,
            path=request.url.path,
            status_code=response.status_code,
            duration_ms=duration_ms,
            user_id=getattr(request.state, "user_id", None),
            organization_id=getattr(request.state, "organization_id", None),
        )
        response.headers[REQUEST_ID_HEADER] = request_id
        return response
