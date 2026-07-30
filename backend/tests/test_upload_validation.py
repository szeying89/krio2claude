import pytest

from app.services.upload_validation import (
    UploadValidationError,
    read_upload_within_limit,
    validate_upload,
)
from tests.pdf_fixture import build_minimal_pdf


class _FakeUploadFile:
    """A minimal async-readable stand-in for FastAPI's UploadFile, so the
    streaming size check can be tested without going through the ASGI
    stack -- exercises exactly the chunked-read/abort-early logic."""

    def __init__(self, content: bytes, chunk_size: int = 4) -> None:
        self._remaining = content
        self._chunk_size = chunk_size
        self.reads: list[int] = []

    async def read(self, size: int = -1) -> bytes:
        # Cap every read at our own small chunk_size regardless of what the
        # caller requests, so tests can exercise the incremental-read loop
        # in fine-grained steps independent of the production code's own
        # (much larger) chunk size constant.
        read_size = self._chunk_size if size == -1 else min(size, self._chunk_size)
        chunk, self._remaining = self._remaining[:read_size], self._remaining[read_size:]
        self.reads.append(len(chunk))
        return chunk


def test_accepts_valid_markdown():
    assert validate_upload("doc.md", b"# hello", max_bytes=1024) == ".md"


def test_accepts_valid_pdf():
    pdf_bytes = build_minimal_pdf("hi")
    assert validate_upload("doc.pdf", pdf_bytes, max_bytes=len(pdf_bytes) + 1) == ".pdf"


def test_rejects_oversized_file():
    with pytest.raises(UploadValidationError, match="exceeding"):
        validate_upload("doc.md", b"x" * 100, max_bytes=10)


def test_rejects_empty_file():
    with pytest.raises(UploadValidationError, match="empty"):
        validate_upload("doc.md", b"", max_bytes=1024)


def test_rejects_unsupported_extension():
    with pytest.raises(UploadValidationError, match="unsupported extension"):
        validate_upload("doc.exe", b"MZ\x90\x00", max_bytes=1024)


def test_rejects_renamed_file_failing_magic_bytes():
    with pytest.raises(UploadValidationError, match="does not match"):
        validate_upload("fake.pdf", b"this is not really a pdf", max_bytes=1024)


def test_rejects_renamed_docx_failing_magic_bytes():
    with pytest.raises(UploadValidationError, match="does not match"):
        validate_upload("fake.docx", b"not a zip archive", max_bytes=1024)


@pytest.mark.asyncio
async def test_read_upload_within_limit_returns_the_full_content_when_under_the_cap():
    file = _FakeUploadFile(b"hello world", chunk_size=4)
    content = await read_upload_within_limit(file, "doc.md", max_bytes=1024)
    assert content == b"hello world"


@pytest.mark.asyncio
async def test_read_upload_within_limit_aborts_as_soon_as_the_cap_is_exceeded():
    """Security-review finding, fixed here: the old `await file.read()`
    call buffered the entire body before any size check ran. This proves
    the new streaming reader stops pulling more chunks once the limit is
    crossed, rather than draining the whole (attacker-controlled) body
    first."""
    file = _FakeUploadFile(b"x" * 1_000_000, chunk_size=4)
    with pytest.raises(UploadValidationError, match="exceeds"):
        await read_upload_within_limit(file, "big.md", max_bytes=10)

    # Only a handful of small chunks were ever pulled before aborting --
    # nowhere near the full 1,000,000-byte body.
    assert sum(file.reads) < 1000


@pytest.mark.asyncio
async def test_read_upload_within_limit_accepts_content_exactly_at_the_cap():
    file = _FakeUploadFile(b"x" * 10, chunk_size=4)
    content = await read_upload_within_limit(file, "doc.md", max_bytes=10)
    assert content == b"x" * 10
