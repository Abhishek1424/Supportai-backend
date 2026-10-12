# What is this file?   Creates the database connection and gives each request its own Session.
# Flutter/Dart idea:   `Engine` = the open Database object (like one `Database` from sqflite).
#                      `Session` = a unit of work / transaction you use for one request.
# Rule in this project: the SERVICE calls commit(). Repositories never commit.
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
# Creates the connection pool ONCE (cached). A pool = a few reusable open connections.
def get_engine() -> Engine:
    """Create the shared connection pool lazily (first use), then reuse it.

    `pool_pre_ping` checks a connection is alive before handing it out, so a
    database restart doesn't cause a burst of errors.
    """
    return create_engine(get_settings().database_url, pool_pre_ping=True)


@lru_cache
# Returns a function that makes new Sessions. Dart idea: a factory/constructor tear-off.
def get_session_factory() -> sessionmaker[Session]:
    """Return the factory that builds Sessions bound to the shared engine.

    `expire_on_commit=False` keeps objects readable after commit, which lets
    services return ORM objects without triggering surprise re-queries.
    """
    return sessionmaker(bind=get_engine(), expire_on_commit=False)


# Dependency that gives every request its own Session and ALWAYS closes it.
# `yield` = "give this to the endpoint, then come back and run the finally part".
# Dart idea: `final db = open(); try { use(db); } finally { db.close(); }`.
# If the service did not commit, closing the session throws the changes away (rollback).
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
