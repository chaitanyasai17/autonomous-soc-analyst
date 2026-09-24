"""
Application lifespan events.

Uses FastAPI's recommended `lifespan` context manager (replaces the
deprecated `@app.on_event("startup"/"shutdown")` decorators).
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.config import get_settings
from app.core.logging import configure_logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: configure logging, log effective settings summary.
    Shutdown: log graceful shutdown (DB connection disposal will be added
    here once a real engine lifecycle needs it — Part 3 only defines the
    engine, it does not require teardown logic yet).
    """
    settings = get_settings()
    configure_logging()
    logger.info(
        "Starting %s (env=%s, debug=%s)",
        settings.APP_NAME,
        settings.APP_ENV.value,
        settings.APP_DEBUG,
    )

    try:
        import uuid
        import app.models
        from app.database.base import Base
        from app.database.session import SessionLocal, engine
        from app.models.enums import UserRole
        from app.models.user import User
        from app.repositories.mitre_repository import MitreRepository
        from app.security.hashing import hash_password

        # Ensure database tables exist
        Base.metadata.create_all(bind=engine)

        with SessionLocal() as db:
            # Seed MITRE catalog
            mitre_repo = MitreRepository(db)
            seeded = mitre_repo.seed_techniques()
            if seeded > 0:
                logger.info("Seeded %d MITRE ATT&CK techniques on startup.", seeded)

            # Seed default admin if missing
            admin_user = db.query(User).filter_by(username="admin").first()
            if not admin_user:
                admin_user = User(
                    id=uuid.uuid4(),
                    username="admin",
                    email="admin@asoc.io",
                    first_name="SOC",
                    last_name="Administrator",
                    role=UserRole.SUPER_ADMIN,
                    password_hash=hash_password("Admin1234!"),
                    is_active=True,
                )
                db.add(admin_user)
                db.commit()
                logger.info("Initialized default administrator: admin / Admin1234!")
    except Exception as err:
        logger.warning("Startup database initialization: %s", err)

    yield

    logger.info("Shutting down %s", settings.APP_NAME)
