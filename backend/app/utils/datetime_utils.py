"""Date & time helper utilities."""

from datetime import datetime, timezone


def utc_now() -> datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


def to_iso8601(value: datetime) -> str:
    """Format a datetime as an ISO-8601 string with explicit UTC offset."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def from_iso8601(value: str) -> datetime:
    """Parse an ISO-8601 string into a timezone-aware datetime."""
    return datetime.fromisoformat(value)
