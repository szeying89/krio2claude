"""Task 22's per-audience PDF export: a minimal, hand-written,
dependency-free PDF writer rather than a third-party HTML-to-PDF engine
— those routinely embed a creation timestamp or a random document ID in
the trailer, which would make "PDF deterministic per model version" false
by construction no matter how deterministic the *content* is. This
writer never writes a timestamp or random bytes anywhere: given the same
markdown text, it produces byte-identical PDF output every time.

Single-page for simplicity (this platform's reports are read as
markdown/HTML normally; the PDF export is a plain, readable rendering of
the same lines, not a typeset document) — lines beyond what fits on one
page are simply included as additional lines further down the content
stream, since PDF has no inherent scroll limit for a content stream (a
real paginated renderer is future work, out of this task's scope).
"""

from __future__ import annotations

_PAGE_WIDTH = 612
_PAGE_HEIGHT = 792
_LEFT_MARGIN = 50
_TOP_MARGIN = 50
_LINE_HEIGHT = 14
_FONT_SIZE = 10
_MAX_LINE_CHARS = 95


def _escape_pdf_string(text: str) -> str:
    return text.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _wrap_line(line: str) -> list[str]:
    if len(line) <= _MAX_LINE_CHARS:
        return [line]
    wrapped = []
    while line:
        wrapped.append(line[:_MAX_LINE_CHARS])
        line = line[_MAX_LINE_CHARS:]
    return wrapped


def markdown_to_pdf_bytes(title: str, markdown_text: str) -> bytes:
    raw_lines = [title, ""] + markdown_text.splitlines()
    lines: list[str] = []
    for line in raw_lines:
        lines.extend(_wrap_line(line))

    content_parts = [f"BT /F1 {_FONT_SIZE} Tf {_LEFT_MARGIN} {_PAGE_HEIGHT - _TOP_MARGIN} Td"]
    for index, line in enumerate(lines):
        prefix = "" if index == 0 else f"0 {-_LINE_HEIGHT} Td "
        content_parts.append(f"{prefix}({_escape_pdf_string(line)}) Tj")
    content_parts.append("ET")
    content_stream = "\n".join(content_parts)
    content_bytes = content_stream.encode("latin-1", errors="replace")

    objects: list[bytes] = []
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    objects.append(b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    objects.append(
        b"<< /Type /Page /Parent 2 0 R /Resources << /Font << /F1 4 0 R >> >> "
        b"/MediaBox [0 0 %d %d] /Contents 5 0 R >>" % (_PAGE_WIDTH, _PAGE_HEIGHT)
    )
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    objects.append(
        b"<< /Length %d >>\nstream\n" % len(content_bytes) + content_bytes + b"\nendstream"
    )

    header = b"%PDF-1.4\n"
    body = bytearray()
    offsets = [0]  # object 0 is always free, offset 0
    body += header
    for index, obj in enumerate(objects, start=1):
        offsets.append(len(body))
        body += b"%d 0 obj\n" % index + obj + b"\nendobj\n"

    xref_offset = len(body)
    xref_lines = [b"xref", b"0 %d" % (len(objects) + 1), b"0000000000 65535 f "]
    for offset in offsets[1:]:
        xref_lines.append(b"%010d 00000 n " % offset)
    body += b"\n".join(xref_lines) + b"\n"
    body += (
        b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF"
        % (len(objects) + 1, xref_offset)
    )
    return bytes(body)
