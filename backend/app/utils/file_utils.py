"""
File utilities.

Generic, storage-agnostic helpers. Domain-specific file handling (e.g., log
upload validation) will live in app/logs (Part 5) and build on these.
"""

import hashlib
import os
import uuid


def get_file_extension(filename: str) -> str:
    """Return the lowercased file extension, without the leading dot."""
    _, ext = os.path.splitext(filename)
    return ext.lstrip(".").lower()


def generate_unique_filename(original_filename: str) -> str:
    """Generate a collision-safe filename that preserves the original extension."""
    ext = get_file_extension(original_filename)
    unique_name = uuid.uuid4().hex
    return f"{unique_name}.{ext}" if ext else unique_name


def is_allowed_extension(filename: str, allowed_extensions: set[str]) -> bool:
    """Check whether a filename's extension is in an allowed set (e.g., {'log', 'csv', 'json'})."""
    return get_file_extension(filename) in allowed_extensions


def human_readable_size(num_bytes: int) -> str:
    """Convert a byte count into a human-readable string (e.g., '4.2 MB')."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} PB"


def compute_sha256(content: bytes) -> str:
    """Compute the SHA-256 hex digest of a byte string (upload integrity/dedup checksum)."""
    return hashlib.sha256(content).hexdigest()
