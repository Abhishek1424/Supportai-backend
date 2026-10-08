"""Database engine and per-request session management.

Transaction rule used across the app: SERVICES own the transaction. A service
method does its work and calls `session.commit()` once at the end, so a request
either fully succeeds or fully rolls back. Repositories never commit.
"""

from collections.abc import Iterator
from functools import lru_cache

from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from app.core.config import get_settings


@lru_cache
def get_engine() -> Engine:
    """Create the shared connection pool lazily (first use), then reuse it.

    `pool_pre_ping` checks a connection is alive before handing it out, so a
    database restart doesn't cause a burst of errors.
    """
    return create_engine(get_settings().database_url, pool_pre_ping=True)


@lru_cache
def get_session_factory() -> sessionmaker[Session]:
    """Return the factory that builds Sessions bound to the shared engine.

    `expire_on_commit=False` keeps objects readable after commit, which lets
    services return ORM objects without triggering surprise re-queries.
    """
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency: yield one Session per request, always close it.

    Flow: route is called -> service uses this session -> service commits
    -> this function's `finally` closes the session (uncommitted work is
    rolled back automatically on close, e.g. when an exception was raised).
    """
    session = get_session_factory()()
    try:
        yield session
    finally:
        session.close()
