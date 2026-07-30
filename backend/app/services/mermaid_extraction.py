"""Fenced-Mermaid-block extraction from prose documents.

Implements the CommonMark fenced-code-block rule that matters here: once
inside a fence, subsequent lines are literal content until a *closing* fence
of the same character and at least the same length is seen — a shorter fence
marker nested inside (e.g. a stray ```mermaid``` example quoted inside a
longer ```` ```` ```` wrapper) does not open a new block and does not close
the outer one. This is what makes "nested fences" behave correctly: only
genuine top-level mermaid fences are extracted.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_OPEN_FENCE_RE = re.compile(r"^(?P<indent>[ \t]*)(?P<fence>`{3,}|~{3,})[ \t]*(?P<lang>[^\s`~]*)")
_MERMAID_LANGS = {"mermaid", "mmd"}


@dataclass(frozen=True)
class MermaidBlock:
    index: int
    source: str
    start_line: int
    end_line: int


def extract_mermaid_blocks(text: str) -> list[MermaidBlock]:
    lines = text.splitlines()
    blocks: list[MermaidBlock] = []

    in_fence = False
    fence_char = ""
    fence_len = 0
    fence_indent = 0
    is_mermaid = False
    current_lines: list[str] = []
    start_line = 0
    index = 0

    def close_fence(end_line: int) -> None:
        nonlocal in_fence, index
        if is_mermaid:
            blocks.append(
                MermaidBlock(
                    index=index,
                    source="\n".join(current_lines),
                    start_line=start_line,
                    end_line=end_line,
                )
            )
            index += 1
        in_fence = False

    for lineno, line in enumerate(lines, start=1):
        if not in_fence:
            match = _OPEN_FENCE_RE.match(line)
            if match:
                in_fence = True
                fence_char = match.group("fence")[0]
                fence_len = len(match.group("fence"))
                fence_indent = len(match.group("indent"))
                is_mermaid = match.group("lang").lower() in _MERMAID_LANGS
                current_lines = []
                start_line = lineno
            continue

        stripped = line.lstrip(" \t")
        run = len(stripped) - len(stripped.lstrip(fence_char))
        rest = stripped[run:].strip()
        if run >= fence_len and rest == "":
            close_fence(lineno)
            continue

        if is_mermaid:
            dedented = line[fence_indent:] if line[:fence_indent].strip() == "" else line
            current_lines.append(dedented)

    if in_fence:
        # Unterminated fence: CommonMark treats it as running to end of document.
        close_fence(len(lines))

    return blocks


def strip_mermaid_blocks(text: str) -> str:
    """Return prose with fenced Mermaid blocks (fences included) removed,
    leaving everything else — including other fenced code blocks — intact."""
    lines = text.splitlines()
    kept: list[str] = []

    in_fence = False
    fence_char = ""
    fence_len = 0
    is_mermaid = False

    for line in lines:
        if not in_fence:
            match = _OPEN_FENCE_RE.match(line)
            if match:
                in_fence = True
                fence_char = match.group("fence")[0]
                fence_len = len(match.group("fence"))
                is_mermaid = match.group("lang").lower() in _MERMAID_LANGS
                if not is_mermaid:
                    kept.append(line)
                continue
            kept.append(line)
            continue

        stripped = line.lstrip(" \t")
        run = len(stripped) - len(stripped.lstrip(fence_char))
        rest = stripped[run:].strip()
        if run >= fence_len and rest == "":
            in_fence = False
            if not is_mermaid:
                kept.append(line)
            continue

        if not is_mermaid:
            kept.append(line)

    return "\n".join(kept)
