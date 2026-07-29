"""Upload type/size validation for design document ingestion.

Extension alone is not trusted: PDF and DOCX are additionally checked
against their magic bytes so a renamed file can't slip past the allowlist.
"""

from __future__ import annotations

from pathlib import PurePosixPath

ALLOWED_EXTENSIONS = {".md", ".txt", ".pdf", ".docx"}

_MAGIC_BYTES: dict[str, bytes] = {
    ".pdf": b"%PDF-",
    ".docx": b"PK\x03\x04",  # DOCX is a zip archive
}


class UploadValidationError(Exception):
    pass


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
