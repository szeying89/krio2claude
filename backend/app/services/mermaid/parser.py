"""Top-level entry point: dispatches to the flowchart or C4 parser based on
the diagram's declared type, so callers don't need to know which grammar a
given Mermaid source uses."""

from __future__ import annotations

from app.services.mermaid.c4_parser import parse_c4
from app.services.mermaid.errors import MermaidParseError
from app.services.mermaid.flowchart_parser import parse_flowchart
from app.services.mermaid.models import ParsedDiagram

_C4_KEYWORDS = ("C4Context", "C4Container", "C4Component", "C4Dynamic", "C4Deployment")


def parse_diagram(text: str) -> ParsedDiagram:
    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        idx = raw_line.find("%%")
        stripped = (raw_line if idx == -1 else raw_line[:idx]).strip()
        if not stripped:
            continue
        if stripped.startswith(_C4_KEYWORDS):
            return parse_c4(text)
        if stripped.split()[0] in ("graph", "flowchart"):
            return parse_flowchart(text)
        raise MermaidParseError(
            line_no,
            1,
            "unrecognized diagram type; expected 'graph', 'flowchart', or a C4 diagram header",
            stripped,
        )
    raise MermaidParseError(1, 1, "empty diagram")
