# =====================  FLUTTER / DART GUIDE FOR THE BACKEND  =====================
#
# What is this file?
#   The starting point of the backend. Like `main()` in a Flutter app.
#   It builds the app, adds common features, and connects all the routes.
#
# THE BIG MENTAL MODEL (the real flow of this project)
#
#   Flutter app you know            |  This backend
#   --------------------------------|----------------------------------------------
#   Screen (button tap)             |  HTTP request arrives (e.g. POST /members)
#     |                             |    |
#   Service / ApiClient (Dio)       |  router.py   = the API endpoint (like a controller)
#     |                             |    |  checks input + permission
#   Repository                      |  service.py  = business rules (like a Service class)
#     |                             |    |
#   Database (sqflite / API)        |  repository.py = only database queries (SQL)
#     |                             |    |
#   Model (fromJson)                |  models.py   = table classes   schemas.py = JSON models
#     |                             |    |
#   Screen shows the data           |  JSON response goes back to the caller
#
# PYTHON -> DART QUICK TRANSLATION (used in every file)
#   def f(x: int) -> str          ~  String f(int x)
#   async def / await             ~  Future<...> f() async / await   (same idea)
#   str | None                    ~  String?   (nullable type)
#   None                          ~  null
#   dict / list                   ~  Map / List
#   class X(BaseModel)  (Pydantic)~  a Dart model class with fromJson + validation built in
#   @dataclass(frozen=True)       ~  a class with only `final` fields (immutable)
#   Enum / StrEnum                ~  enum (StrEnum = enum whose values are Strings)
#   raise MyError(...)            ~  throw MyError(...)
#   try / except                  ~  try / catch
#   with x: ... / yield           ~  try { ... } finally { cleanup }
#   self                          ~  this
#   __init__                      ~  the constructor
#   @decorator                    ~  an annotation that ALSO changes behaviour
#                                    (Dart annotations do nothing by themselves)
#   Depends(f)                    ~  dependency injection: the framework calls f()
#                                    and passes the result as a parameter. Like
#                                    context.read<T>() or a constructor argument,
#                                    but done automatically.
#   Protocol                      ~  abstract class / interface
#   # comment                     ~  // comment
#
# Not exact equivalents. They are only to help you read the code.
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

# Every API URL starts with /api/v1. The "v1" lets us release v2 later
# without breaking old apps. Flutter idea: a `baseUrl` constant in Dio.
API_V1_PREFIX = "/api/v1"


# Builds the whole app. This is called a "factory function".
# Flutter idea: like a function that returns your `MaterialApp(...)`.
# Why a function and not a global variable? Tests can build a fresh app
# with different settings. Nothing heavy runs when the file is imported.
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
    # Read the config (env values). Flutter idea: reading values from
    # `--dart-define` or a config class. See core/config.py.
    settings = get_settings()
    configure_logging(settings.app_env)

    # `FastAPI(...)` creates the app object. It is like `runApp(MaterialApp(...))`,
    # but for a server. Docs are turned off in production to hide the API map.
    app = FastAPI(
        title="SupportAI API",
        version="0.1.0",
        # Interactive docs are handy in dev, an unnecessary attack surface in prod.
        docs_url=None if settings.app_env == "production" else "/docs",
        redoc_url=None,
    )
    # Middleware = code that runs for EVERY request before/after the endpoint.
    # Flutter idea: a Dio `Interceptor`, but on the server side.
    # CORS = browser safety rule about which websites may call this API.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,  # explicit allow-list; never "*" with credentials
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", REQUEST_ID_HEADER],
        expose_headers=[REQUEST_ID_HEADER],
    )
    app.add_middleware(RequestContextMiddleware)
    # Tell the app: "when any error happens, turn it into our standard JSON".
    # Flutter idea: one global try/catch + error mapper for the whole app.
    register_exception_handlers(app)

    # A router groups endpoints. Here we gather all routers under /api/v1.
    # Flutter idea: a route table, like go_router's list of GoRoute.
    api_v1 = APIRouter(prefix=API_V1_PREFIX)
    api_v1.include_router(auth_router)
    api_v1.include_router(organizations_router)
    api_v1.include_router(audit_router)
    app.include_router(api_v1)

    # A tiny endpoint to ask "is the server alive?". Tools like Docker call it.
    # The `@app.get(...)` line is a DECORATOR: it registers the function below
    # as the handler for GET /health. Think: `GoRoute(path: '/health', builder: ...)`.
    @app.get("/health", tags=["system"])
    def health() -> dict[str, str]:
        """Liveness probe for load balancers/containers (does not touch the database)."""
        return {"status": "ok"}

    # Only in development: opening "/" redirects to the docs page.
    if settings.app_env != "production":

        @app.get("/", include_in_schema=False)
        def root() -> RedirectResponse:
            """Dev convenience: send browsers hitting the bare URL to the API docs.

            Not registered in production, where the docs page is disabled too.
            """
            return RedirectResponse(url="/docs")

    return app


# Create the one app object. The server (uvicorn) looks for this name:
# `uvicorn app.main:app`. Flutter idea: the object `runApp` receives.
app = create_app()
