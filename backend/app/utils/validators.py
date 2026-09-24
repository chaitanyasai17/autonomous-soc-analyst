"""Reusable, cross-domain validators."""

import re

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
# Minimum 8 chars, at least one letter and one digit — a baseline check only;
# the final password policy will be finalized alongside auth in Part 4.
_PASSWORD_MIN_LENGTH = 8

_MAX_FILENAME_LENGTH = 255
_UNSAFE_FILENAME_CHARS = set('/\\\x00')


def is_valid_email(value: str) -> bool:
    """Basic structural email validation (not a full RFC 5322 implementation)."""
    return bool(_EMAIL_RE.match(value))


def is_strong_password(value: str) -> bool:
    """Baseline password strength check: length + letter + digit."""
    if len(value) < _PASSWORD_MIN_LENGTH:
        return False
    has_letter = any(char.isalpha() for char in value)
    has_digit = any(char.isdigit() for char in value)
    return has_letter and has_digit


def is_non_empty_string(value: str | None) -> bool:
    """Check that a string is present and not just whitespace."""
    return bool(value and value.strip())


def is_safe_filename(filename: str | None) -> bool:
    """
    Reject filenames that could enable directory traversal or other
    filesystem abuse: path separators, null bytes, ".." sequences, control
    characters, empty/whitespace-only names, or names exceeding a sane
    length. Used by the upload module (Part 5) before any filename derived
    from client input touches the filesystem or database.
    """
    if not filename or not filename.strip():
        return False
    if len(filename) > _MAX_FILENAME_LENGTH:
        return False
    if any(char in _UNSAFE_FILENAME_CHARS for char in filename):
        return False
    if ".." in filename:
        return False
    if any(ord(char) < 32 for char in filename):
        return False
    return True
