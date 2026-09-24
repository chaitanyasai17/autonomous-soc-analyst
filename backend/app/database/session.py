"""
Database engine and session factory.

No ORM models, tables, or migrations are defined here — this module only
provides the plumbing (`engine`, `SessionLocal`) that repositories/ and
dependencies/ build on.
"""

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from app.config import get_settings

settings = get_settings()

connect_args = {}
if settings.DATABASE_URL and settings.DATABASE_URL.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

# `pool_pre_ping` avoids handing out stale/dead connections after DB restarts.
engine: Engine = create_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    connect_args=connect_args,
    future=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autocommit=False,
    autoflush=False,
    future=True,
)


def get_db_session() -> Session:
    """
    Return a new SQLAlchemy Session.

    Prefer using the `get_db` FastAPI dependency (app/dependencies/database.py)
    inside request handlers; use this directly only for scripts/tooling
    outside the request lifecycle.
    """
    return SessionLocal()
