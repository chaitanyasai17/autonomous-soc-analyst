"""
Local filesystem storage backend for uploaded files.

Deliberately a small class (not free functions) so a future storage
backend (e.g., S3) can be swapped in behind the same
save/delete/exists/absolute_path interface without touching callers —
this is the Strategy Pattern referenced in the master project blueprint.

All paths are resolved relative to a configured base directory (from
Settings, never hardcoded) and defensively checked to ensure the resolved
path never escapes that base directory, even though the relative paths
this module currently receives are server-generated (UUID-based), not
directly user-controlled.
"""

from pathlib import Path


class StoragePathError(Exception):
    """Raised when a resolved storage path would escape the base directory."""


class LocalFileStorage:
    def __init__(self, base_directory: str):
        self.base_directory = Path(base_directory)
        self.base_directory.mkdir(parents=True, exist_ok=True)

    def _resolve(self, relative_path: str) -> Path:
        base_resolved = self.base_directory.resolve()
        candidate = (self.base_directory / relative_path).resolve()
        if base_resolved not in candidate.parents and candidate != base_resolved:
            raise StoragePathError("Resolved path escapes the storage base directory.")
        return candidate

    def save(self, content: bytes, relative_path: str) -> None:
        path = self._resolve(relative_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    def delete(self, relative_path: str) -> None:
        path = self._resolve(relative_path)
        if path.exists():
            path.unlink()

    def exists(self, relative_path: str) -> bool:
        return self._resolve(relative_path).exists()

    def read(self, relative_path: str) -> bytes:
        """Read a stored file's full contents. Used by the parser engine (Part 6)."""
        return self._resolve(relative_path).read_bytes()

    def absolute_path(self, relative_path: str) -> Path:
        return self._resolve(relative_path)
