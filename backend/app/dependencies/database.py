"""
Database dependency provider.

Yields a request-scoped SQLAlchemy session and guarantees it is closed
after the request completes, even if an exception is raised.
"""

from typing import Generator

from sqlalchemy.orm import Session

from app.database import SessionLocal


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: `db: Session = Depends(get_db)`."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
