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
        from app.security.hashing import hash_password, verify_password

        # Ensure database tables exist
        try:
            from app.database.session import engine as current_engine
            Base.metadata.create_all(bind=current_engine)
        except Exception as db_init_err:
            logger.warning("Primary database table creation failed (%s). Falling back to local resilient SQLite storage.", db_init_err)
            from app.database.session import fallback_to_sqlite
            new_engine = fallback_to_sqlite()
            Base.metadata.create_all(bind=new_engine)

        with SessionLocal() as db:
            # Seed MITRE catalog
            mitre_repo = MitreRepository(db)
            seeded = mitre_repo.seed_techniques()
            if seeded > 0:
                logger.info("Seeded %d MITRE ATT&CK techniques on startup.", seeded)

            # Provision administrator accounts on startup
            admin_role_str = (settings.ADMIN_ROLE or "super_admin").lower()
            try:
                role_enum = UserRole(admin_role_str)
            except ValueError:
                role_enum = UserRole.SUPER_ADMIN

            accounts_to_seed = [
                {
                    "username": "chaitu",
                    "email": "chaitu@asoc.io",
                    "password": "412065",
                    "role": UserRole.SUPER_ADMIN,
                    "first_name": "Chaitu",
                    "last_name": "Admin",
                },
                {
                    "username": "chaitanayasai17",
                    "email": "chaitanayasai17@asoc.io",
                    "password": "412065",
                    "role": UserRole.SUPER_ADMIN,
                    "first_name": "Chaitanya",
                    "last_name": "Sai",
                },
                {
                    "username": "admin",
                    "email": "admin@asoc.io",
                    "password": "412065",
                    "role": UserRole.SUPER_ADMIN,
                    "first_name": "SOC",
                    "last_name": "Administrator",
                },
            ]

            if settings.ADMIN_USERNAME and settings.ADMIN_PASSWORD:
                accounts_to_seed.append({
                    "username": settings.ADMIN_USERNAME,
                    "email": getattr(settings, "ADMIN_EMAIL", f"{settings.ADMIN_USERNAME}@asoc.io"),
                    "password": settings.ADMIN_PASSWORD,
                    "role": role_enum,
                    "first_name": "SOC",
                    "last_name": "Administrator",
                })

            for acc in accounts_to_seed:
                u_name = acc["username"]
                u_pwd = acc["password"]
                u_email = acc["email"]
                user = db.query(User).filter(User.username == u_name).first()
                if not user:
                    user = User(
                        id=uuid.uuid4(),
                        username=u_name,
                        email=u_email,
                        first_name=acc["first_name"],
                        last_name=acc["last_name"],
                        role=acc["role"],
                        password_hash=hash_password(u_pwd),
                        is_active=True,
                    )
                    db.add(user)
                    db.commit()
                    logger.info("Initialized administrator account for '%s' (role: %s).", u_name, acc["role"].value)
                else:
                    if not verify_password(u_pwd, user.password_hash):
                        user.password_hash = hash_password(u_pwd)
                        db.commit()
                        logger.info("Synchronized administrator credentials for '%s'.", u_name)
    except Exception as err:
        logger.warning("Startup database initialization: %s", err)

    yield

    logger.info("Shutting down %s", settings.APP_NAME)
