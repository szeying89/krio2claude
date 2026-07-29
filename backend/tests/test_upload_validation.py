import pytest

from app.services.upload_validation import UploadValidationError, validate_upload
from tests.pdf_fixture import build_minimal_pdf


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
