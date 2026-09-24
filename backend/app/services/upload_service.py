"""
Upload service — orchestrates validation, checksum, disk storage, and
SecurityLog persistence for the Log Upload Module (Part 5).

Extensibility note: adding support for a new file format requires touching
only the two registries below (`_ALLOWED_MIME_TYPES_BY_EXTENSION` and
`_CONTENT_VALIDATORS`) plus adding the extension to
`settings.ALLOWED_UPLOAD_EXTENSIONS` — no branching logic elsewhere in this
class changes. This module does not parse log CONTENT for meaning (that's
Part 6) — content validators here only sanity-check that a file's bytes are
plausibly the format its extension claims.
"""

from __future__ import annotations

import json
import mimetypes
import uuid
from datetime import datetime
from typing import Callable, Sequence

from fastapi import UploadFile

from app.config import get_settings
from app.core.exceptions import ConflictError, ForbiddenError, NotFoundError, ValidationFailedError
from app.models.enums import LogSource, ProcessingStatus
from app.models.security_log import SecurityLog
from app.models.user import User
from app.repositories.security_log_repository import SecurityLogRepository
from app.security.permissions import Permission, role_has_permission
from app.utils.datetime_utils import utc_now
from app.utils.file_utils import compute_sha256, generate_unique_filename, get_file_extension
from app.utils.storage import LocalFileStorage
from app.utils.validators import is_safe_filename

_READ_CHUNK_SIZE = 1024 * 1024  # 1 MB


def _validate_text_decodable(content: bytes) -> bool:
    """CSV/TXT/LOG sanity check: content must be decodable as text, not arbitrary binary."""
    try:
        content.decode("utf-8")
        return True
    except UnicodeDecodeError:
        try:
            content.decode("latin-1")
            return True
        except UnicodeDecodeError:
            return False


def _validate_json_content(content: bytes) -> bool:
    """
    Accepts either a single JSON document or newline-delimited JSON (NDJSON)
    — security log exports commonly use NDJSON (one event per line), which
    `json.loads()` on the whole file would incorrectly reject.
    """
    text = content.decode("utf-8", errors="ignore").strip()
    if not text:
        return False
    try:
        json.loads(text)
        return True
    except json.JSONDecodeError:
        pass
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            json.loads(line)
            return True
        except json.JSONDecodeError:
            return False
    return False


_CONTENT_VALIDATORS: dict[str, Callable[[bytes], bool]] = {
    "csv": _validate_text_decodable,
    "txt": _validate_text_decodable,
    "log": _validate_text_decodable,
    "json": _validate_json_content,
}

_ALLOWED_MIME_TYPES_BY_EXTENSION: dict[str, set[str]] = {
    "csv": {"text/csv", "application/vnd.ms-excel", "text/plain", "application/octet-stream"},
    "json": {"application/json", "text/plain", "application/octet-stream"},
    "log": {"text/plain", "application/octet-stream"},
    "txt": {"text/plain", "application/octet-stream"},
}


class UploadService:
    """Application-layer service for the log upload lifecycle."""

    def __init__(self, repository: SecurityLogRepository, storage: LocalFileStorage):
        self.repository = repository
        self.storage = storage

    # --- Upload ---

    async def upload(self, file: UploadFile, uploader: User, log_source: LogSource) -> SecurityLog:
        settings = get_settings()

        if not is_safe_filename(file.filename):
            raise ValidationFailedError("Invalid or unsafe filename.")

        extension = get_file_extension(file.filename)
        if extension not in settings.ALLOWED_UPLOAD_EXTENSIONS:
            allowed = ", ".join(settings.ALLOWED_UPLOAD_EXTENSIONS)
            raise ValidationFailedError(
                f"Unsupported file extension '.{extension}'. Allowed extensions: {allowed}."
            )

        content = await self._read_with_size_limit(file, settings.MAX_UPLOAD_SIZE_BYTES)
        if len(content) == 0:
            raise ValidationFailedError("Uploaded file is empty.")

        content_validator = _CONTENT_VALIDATORS.get(extension)
        if content_validator is not None and not content_validator(content):
            raise ValidationFailedError(
                f"File content does not appear to be valid {extension.upper()}."
            )

        mime_type = self._resolve_and_validate_mime_type(file.content_type, extension)
        checksum = compute_sha256(content)

        unique_filename = generate_unique_filename(file.filename)
        now = utc_now()
        # Date-partitioned so a single directory never accumulates every
        # upload the system has ever received.
        relative_path = f"{now:%Y/%m/%d}/{unique_filename}"

        self.storage.save(content, relative_path)

        security_log = SecurityLog(
            filename=unique_filename,
            original_filename=file.filename,
            log_source=log_source,
            file_type=extension,
            uploaded_by_id=uploader.id,
            upload_time=now,
            processing_status=ProcessingStatus.PENDING,
            file_size=len(content),
            mime_type=mime_type,
            storage_path=relative_path,
            checksum_sha256=checksum,
        )

        try:
            return self.repository.create(security_log)
        except Exception:
            # Avoid orphaning a file on disk if the DB write fails.
            self.storage.delete(relative_path)
            raise

    async def _read_with_size_limit(self, file: UploadFile, max_bytes: int) -> bytes:
        """Stream the upload in chunks, aborting as soon as the size limit is exceeded
        rather than buffering an oversized file fully into memory first."""
        buffer = bytearray()
        total = 0
        while True:
            chunk = await file.read(_READ_CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                max_mb = max_bytes / (1024 * 1024)
                raise ValidationFailedError(f"File exceeds the maximum allowed size of {max_mb:.0f}MB.")
            buffer.extend(chunk)
        return bytes(buffer)

    def _resolve_and_validate_mime_type(self, client_content_type: str | None, extension: str) -> str:
        allowed = _ALLOWED_MIME_TYPES_BY_EXTENSION.get(extension, set())
        if client_content_type:
            if client_content_type not in allowed:
                raise ValidationFailedError(
                    f"MIME type '{client_content_type}' is not allowed for .{extension} files."
                )
            return client_content_type
        guessed, _ = mimetypes.guess_type(f"file.{extension}")
        return guessed or "application/octet-stream"

    # --- Read / list ---

    def list_uploads(
        self,
        *,
        requesting_user: User,
        log_source: LogSource | None = None,
        processing_status: ProcessingStatus | None = None,
        file_type: str | None = None,
        uploaded_by_username: str | None = None,
        upload_date_from: datetime | None = None,
        upload_date_to: datetime | None = None,
        file_size_min: int | None = None,
        file_size_max: int | None = None,
        search: str | None = None,
        skip: int = 0,
        limit: int = 20,
        sort_by: str = "upload_time",
        sort_order: str = "desc",
    ) -> tuple[Sequence[SecurityLog], int]:
        """Users without LOG_READ_ANY only ever see their own uploads."""
        uploaded_by_id = None
        if not role_has_permission(requesting_user.role, Permission.LOG_READ_ANY):
            uploaded_by_id = requesting_user.id

        return self.repository.search(
            uploaded_by_id=uploaded_by_id,
            uploaded_by_username=uploaded_by_username,
            log_source=log_source,
            processing_status=processing_status,
            file_type=file_type,
            upload_date_from=upload_date_from,
            upload_date_to=upload_date_to,
            file_size_min=file_size_min,
            file_size_max=file_size_max,
            search=search,
            skip=skip,
            limit=limit,
            sort_by=sort_by,
            sort_order=sort_order,
        )

    def get_upload_or_404(self, log_id: uuid.UUID, requesting_user: User) -> SecurityLog:
        security_log = self.repository.get_by_id(log_id)
        if security_log is None:
            raise NotFoundError(f"Security log with id={log_id} not found.")

        is_owner = security_log.uploaded_by_id == requesting_user.id
        has_visibility = role_has_permission(requesting_user.role, Permission.LOG_READ_ANY)
        if not is_owner and not has_visibility:
            # Mirrors Part 4's anti-enumeration approach: don't distinguish
            # "doesn't exist" from "exists but you can't see it".
            raise NotFoundError(f"Security log with id={log_id} not found.")

        return security_log

    # --- Delete ---

    def delete_upload(self, security_log: SecurityLog, requesting_user: User) -> None:
        is_owner = security_log.uploaded_by_id == requesting_user.id
        has_elevated_permission = role_has_permission(requesting_user.role, Permission.LOG_DELETE)
        if not is_owner and not has_elevated_permission:
            raise ForbiddenError("You do not have permission to delete this upload.")

        if security_log.processing_status not in (ProcessingStatus.PENDING, ProcessingStatus.FAILED):
            raise ConflictError(
                "Cannot delete a log that has already been processed or is currently processing."
            )

        self.storage.delete(security_log.storage_path)
        self.repository.delete(security_log)
