"""Decompression-bomb guard for uploads that are zip containers under the
hood (DOCX, XLSX) -- both `python-docx` and `openpyxl` unzip their
internal XML unconditionally, and the upload size cap
(`TM_MAX_UPLOAD_BYTES`) only bounds the *compressed* size. A small,
maliciously-crafted archive can still expand to an enormous decompressed
size, exhausting memory before either library ever returns.

Checked directly against the archive's own central directory (which
records each member's uncompressed size) before handing the stream to
either parsing library -- no decompression happens here at all.
"""

from __future__ import annotations

import zipfile
from pathlib import Path
from typing import IO

DEFAULT_MAX_UNCOMPRESSED_BYTES = 200_000_000
DEFAULT_MAX_COMPRESSION_RATIO = 100


class ZipBombError(Exception):
    pass


def reject_if_zip_bomb(
    source: str | Path | IO[bytes],
    *,
    max_uncompressed_bytes: int = DEFAULT_MAX_UNCOMPRESSED_BYTES,
    max_compression_ratio: int = DEFAULT_MAX_COMPRESSION_RATIO,
) -> None:
    """Raises `ZipBombError` if `source` (a zip container -- a path or an
    open, seekable stream, exactly like `zipfile.ZipFile`'s own `file`
    argument) would expand to an unreasonable size, or has an anomalous
    compression ratio. If `source` is a stream, its position is restored
    on return so the caller can still hand it to the real parser
    afterward. Not a zip file at all is not this function's concern -- it
    re-raises `zipfile.BadZipFile` unchanged for the caller's own
    format-error handling."""
    start = source.tell() if hasattr(source, "tell") else None
    try:
        with zipfile.ZipFile(source) as archive:
            compressed_total = sum(info.compress_size for info in archive.infolist())
            uncompressed_total = sum(info.file_size for info in archive.infolist())
    finally:
        if start is not None:
            source.seek(start)  # type: ignore[union-attr]

    if uncompressed_total > max_uncompressed_bytes:
        raise ZipBombError(
            f"archive would decompress to {uncompressed_total} bytes, "
            f"exceeding the {max_uncompressed_bytes} byte limit"
        )
    if compressed_total > 0 and uncompressed_total / compressed_total > max_compression_ratio:
        raise ZipBombError(
            f"archive's compression ratio ({uncompressed_total / compressed_total:.1f}:1) "
            f"exceeds the allowed {max_compression_ratio}:1"
        )
