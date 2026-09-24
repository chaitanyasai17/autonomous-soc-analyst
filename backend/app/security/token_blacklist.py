"""
Refresh token revocation (blacklist) store.

Enables logout and refresh-token rotation: a token's `jti` claim is recorded
here once it's used/revoked and rejected on subsequent use.

IMPORTANT — single-process limitation:
    This implementation is an in-memory set, which is correct for a single
    Uvicorn worker but is NOT shared across multiple worker processes or
    horizontally-scaled instances. For a multi-worker/multi-instance
    production deployment, replace the storage backend with a shared store
    (e.g., Redis with TTL matching the refresh token's expiry) — the
    `is_revoked` / `revoke` function signatures below would not need to
    change for calling code, only their internal implementation.
"""

import threading

_revoked_jtis: set[str] = set()
_lock = threading.Lock()


def revoke(jti: str) -> None:
    """Mark a token's jti as revoked."""
    with _lock:
        _revoked_jtis.add(jti)


def is_revoked(jti: str) -> bool:
    """Check whether a token's jti has been revoked."""
    with _lock:
        return jti in _revoked_jtis
