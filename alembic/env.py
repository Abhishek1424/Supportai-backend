"""Alembic environment: tells Alembic which database and which models to use."""

from logging.config import fileConfig

from sqlalchemy import create_engine

from alembic import context
from app.core.config import get_settings
from app.db.base import Base

# Importing the models registers their tables on Base.metadata (needed for autogenerate).
from app.modules.audit import models as _audit  # noqa: F401
from app.modules.auth import models as _auth  # noqa: F401
from app.modules.organizations import models as _orgs  # noqa: F401
from app.modules.users import models as _users  # noqa: F401

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def run_migrations_online() -> None:
    """Run migrations against the live database from DATABASE_URL.

    Flow: build an engine from app settings -> open a connection -> run all
    pending migrations inside one transaction (Postgres supports transactional DDL,
    so a failed migration leaves no half-applied changes).
    """
    engine = create_engine(get_settings().database_url)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()


run_migrations_online()
