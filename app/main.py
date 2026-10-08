"""Application entry point: builds the FastAPI app and wires everything together."""

from fastapi import APIRouter, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse

from app.core.config import get_settings
from app.core.errors import register_exception_handlers
from app.core.logging import REQUEST_ID_HEADER, RequestContextMiddleware, configure_logging
from app.modules.audit.router import router as audit_router
from app.modules.auth.router import router as auth_router
from app.modules.organizations.router import router as organizations_router

API_V1_PREFIX = "/api/v1"


def create_app() -> FastAPI:
    """Application factory.

    Why a factory: tests can build a fresh app after changing settings, and
    nothing heavy happens at import time.

    Flow: configure logging -> create app -> add middleware -> register error
    handlers -> mount versioned routers.

    Middleware order matters: Starlette runs the LAST added middleware first,
    so RequestContextMiddleware is added last to wrap everything (including
    CORS) and give even CORS-rejected requests a request_id.
    """
    settings = get_settings()
    configure_logging(settings.app_env)

    app = FastAPI(
        title="SupportAI API",
        version="0.1.0",
        # Interactive docs are handy in dev, an unnecessary attack surface in prod.
        docs_url=None if settings.app_env == "production" else "/docs",
        redoc_url=None,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,  # explicit allow-list; never "*" with credentials
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER],
        expose_headers=[REQUEST_ID_HEADER],
    )
    app.add_middleware(RequestContextMiddleware)
    register_exception_handlers(app)

    api_v1 = APIRouter(prefix=API_V1_PREFIX)
    api_v1.include_router(auth_router)
    api_v1.include_router(organizations_router)
    api_v1.include_router(audit_router)
    app.include_router(api_v1)

    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        """Liveness probe for load balancers/containers (does not touch the database)."""
        return {"status": "ok"}

    if settings.app_env != "production":

        @app.get("/", include_in_schema=False)
        def root() -> RedirectResponse:
            """Dev convenience: send browsers hitting the bare URL to the API docs.

            Not registered in production, where the docs page is disabled too.
            """
            return RedirectResponse(url="/docs")

    return app


app = create_app()
