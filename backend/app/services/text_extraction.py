"""Per-format text extraction and normalisation for uploaded design docs."""

from __future__ import annotations

import io

import docx
from pypdf import PdfReader


class TextExtractionError(Exception):
    pass


def _normalise(text: str) -> str:
    # Normalise line endings and strip a leading UTF-8 BOM if present.
    return text.replace("\r\n", "\n").replace("\r", "\n").lstrip("﻿")


def extract_markdown_or_text(raw: bytes) -> str:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TextExtractionError(f"not valid UTF-8 text: {exc}") from exc
    return _normalise(text)


def extract_pdf(raw: bytes) -> str:
    try:
        reader = PdfReader(io.BytesIO(raw))
        pages = [page.extract_text() or "" for page in reader.pages]
    except Exception as exc:  # pypdf raises a variety of format-specific errors
        raise TextExtractionError(f"could not parse PDF: {exc}") from exc
    return _normalise("\n\n".join(pages))


def extract_docx(raw: bytes) -> str:
    try:
        document = docx.Document(io.BytesIO(raw))
        paragraphs = [p.text for p in document.paragraphs]
    except Exception as exc:
        raise TextExtractionError(f"could not parse DOCX: {exc}") from exc
    return _normalise("\n".join(paragraphs))


EXTRACTORS = {
    ".md": extract_markdown_or_text,
    ".txt": extract_markdown_or_text,
    ".pdf": extract_pdf,
    ".docx": extract_docx,
}


def extract_text(extension: str, raw: bytes) -> str:
    try:
        extractor = EXTRACTORS[extension]
    except KeyError as exc:
        raise TextExtractionError(f"no extractor registered for {extension!r}") from exc
    return extractor(raw)
