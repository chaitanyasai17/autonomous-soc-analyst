"""
Alembic migration environment.

Wired to app.config.get_settings() for the database URL (single source of
truth — alembic.ini's sqlalchemy.url is never used) and app.database.Base
for target_metadata.

IMPORTANT: No models are imported here yet. Once app/models/ gains real
ORM classes (Part 3+), they must be imported in this file so Alembic's
autogenerate can detect them — a one-line addition, not a redesign.
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from app.config import get_settings
from app.database import Base

# Importing app.models registers every ORM model on Base's mapper registry —
# required so Base.metadata (used below) is aware of all tables when
# `alembic revision --autogenerate` runs.
import app.models  # noqa: F401

# --- Alembic Config object, provides access to values in alembic.ini ---
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# --- Inject the real database URL from application Settings ---
settings = get_settings()
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# --- Target metadata for 'autogenerate' support ---
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (no DB connection required)."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (using a live DB connection)."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
