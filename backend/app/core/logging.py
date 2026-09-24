"""
Logging configuration.

Configures Python's standard `logging` module for the whole application.
Reads its level from Settings (config/) but owns HOW logging is set up —
that distinction is the core/ vs config/ boundary described in config/settings.py.
"""

import logging
import sys

from app.config import get_settings

LOG_FORMAT = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
LOG_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def configure_logging() -> None:
    """
    Configure the root logger for the application.

    Called once during application startup (see core/lifespan.py).
    """
    settings = get_settings()

    logging.basicConfig(
        level=settings.LOG_LEVEL.upper(),
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        stream=sys.stdout,
        force=True,
    )

    # Quiet noisy third-party loggers unless we're debugging.
    if not settings.APP_DEBUG:
        logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

    logging.getLogger(settings.APP_NAME).info(
        "Logging configured (level=%s, env=%s)", settings.LOG_LEVEL, settings.APP_ENV.value
    )


def get_logger(name: str) -> logging.Logger:
    """Convenience accessor so other modules don't import `logging` directly."""
    return logging.getLogger(name)
