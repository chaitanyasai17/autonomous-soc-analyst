"""
Password hashing utilities.

Pure functions only — no user lookup, no endpoints. Consumed by
app/users (Part 4) and app/dependencies (auth dependency, Part 4).
"""

import bcrypt
from passlib.context import CryptContext

# Compatibility shim for passlib with bcrypt >= 4.1.0
if not hasattr(bcrypt, "__about__"):
    bcrypt.__about__ = type("About", (), {"__version__": getattr(bcrypt, "__version__", "4.1.0")})

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain_password: str) -> str:
    """Hash a plaintext password for storage."""
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a stored bcrypt hash."""
    return _pwd_context.verify(plain_password, hashed_password)
