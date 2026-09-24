"""General-purpose helper functions."""

from typing import Any


def chunked(items: list[Any], size: int) -> list[list[Any]]:
    """Split a list into chunks of at most `size` elements."""
    return [items[i : i + size] for i in range(0, len(items), size)]


def clamp(value: int | float, minimum: int | float, maximum: int | float) -> int | float:
    """Clamp a numeric value between minimum and maximum (inclusive)."""
    return max(minimum, min(value, maximum))


def safe_get(dictionary: dict, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dict keys, returning `default` if any key is missing."""
    current: Any = dictionary
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current
