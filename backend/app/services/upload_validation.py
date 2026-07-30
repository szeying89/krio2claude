"""Upload type/size validation for design document ingestion.

Extension alone is not trusted: PDF and DOCX are additionally checked
against their magic bytes so a renamed file can't slip past the allowlist.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Protocol

ALLOWED_EXTENSIONS = {".md", ".txt", ".pdf", ".docx"}

_READ_CHUNK_BYTES = 65536


class _AsyncReadable(Protocol):
    async def read(self, size: int = ...) -> bytes: ...

_MAGIC_BYTES: dict[str, bytes] = {
    ".pdf": b"%PDF-",
    ".docx": b"PK\x03\x04",  # DOCX is a zip archive
}


class UploadValidationError(Exception):
    pass


async def read_upload_within_limit(file: _AsyncReadable, filename: str, max_bytes: int) -> bytes:
    """Security-review finding, fixed here: the upload endpoints previously
    did a single unbounded `await file.read()`, buffering the entire
    request body in memory/spooled temp storage *before* the size cap was
    ever checked -- a client could stream an arbitrarily large body and
    the server would fully absorb it before rejecting it. This reads in
    fixed-size chunks and aborts the moment the declared limit is
    exceeded, mirroring the same fix already applied to outbound fetches
    in app/services/intel/fetch.py.
    """
    chunks = bytearray()
    while True:
        chunk = await file.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        chunks.extend(chunk)
        if len(chunks) > max_bytes:
            raise UploadValidationError(
                f"file {filename!r} exceeds the {max_bytes} byte limit"
            )
    return bytes(chunks)


def validate_upload_size(filename: str, content: bytes, max_bytes: int) -> None:
    """Enforce Task 24's upload-limit requirement: shared by every upload
    endpoint (design documents, CRI workbooks) so the limit is enforced
    once, not re-implemented per endpoint."""
    if len(content) > max_bytes:
        raise UploadValidationError(
            f"file {filename!r} is {len(content)} bytes, exceeding the {max_bytes} byte limit"
        )
    if len(content) == 0:
        raise UploadValidationError(f"file {filename!r} is empty")


def validate_upload(filename: str, content: bytes, max_bytes: int) -> str:
    """Validate an uploaded file's extension, size, and magic bytes.

    Returns the validated (lowercased) extension on success.
    """
    validate_upload_size(filename, content, max_bytes)

    extension = PurePosixPath(filename).suffix.lower()
    if extension not in ALLOWED_EXTENSIONS:
        raise UploadValidationError(
            f"file {filename!r} has unsupported extension {extension!r}; "
            f"allowed: {sorted(ALLOWED_EXTENSIONS)}"
        )

    magic = _MAGIC_BYTES.get(extension)
    if magic is not None and not content.startswith(magic):
        raise UploadValidationError(
            f"file {filename!r} does not match the expected {extension} format"
        )

    return extension
