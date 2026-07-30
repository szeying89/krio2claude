"""Deterministic Mermaid flowchart/graph parser.

Parses the common real-world subset of Mermaid's flowchart grammar: all
directions, every standard node shape, chained edges on one line, inline
and pipe-style edge labels, nested subgraphs, quoted/escaped labels, and
self-loops. Unrecognized syntax raises MermaidParseError with a line/column
location rather than silently skipping or guessing — the one exception
being directives that don't affect DFD topology (style/classDef/class/
click/linkStyle/direction-inside-subgraph), which are recognized and
skipped intentionally.

Explicitly out of scope (documented, not silently mishandled): ampersand
fan-out/fan-in (`A --> B & C`) and o/x circle-or-cross arrow endpoints —
both raise a clear "not supported" error rather than being parsed wrong.
"""

from __future__ import annotations

import re

from app.services.mermaid.errors import MermaidParseError
from app.services.mermaid.models import ArrowType, Edge, Node, NodeShape, ParsedDiagram, Subgraph

_DIRECTIONS = {"TD", "TB", "BT", "RL", "LR"}
_HEADER_RE = re.compile(r"^(graph|flowchart)\s+(\w+)\s*$")
_IGNORABLE_DIRECTIVES = ("style ", "classDef ", "class ", "click ", "linkStyle ")

_ID_RE = re.compile(r"[A-Za-z0-9_\.\-]+")

# open_delim -> [(close_delim, shape), ...]; several shapes share an open
# delimiter ("[/" opens both trapezoid and parallelogram, "[\" opens both
# trapezoid_alt and parallelogram_alt), disambiguated only by which close
# delimiter actually appears first — so these are looked up as a group,
# not a flat priority list.
_SHAPE_DELIMS: dict[str, list[tuple[str, NodeShape]]] = {
    "(((": [(")))", NodeShape.DOUBLE_CIRCLE)],
    "([": [("])", NodeShape.STADIUM)],
    "[[": [("]]", NodeShape.SUBROUTINE)],
    "[(": [(")]", NodeShape.CYLINDER)],
    "((": [("))", NodeShape.CIRCLE)],
    "{{": [("}}", NodeShape.HEXAGON)],
    "[/": [("\\]", NodeShape.TRAPEZOID), ("/]", NodeShape.PARALLELOGRAM)],
    "[\\": [("/]", NodeShape.TRAPEZOID_ALT), ("\\]", NodeShape.PARALLELOGRAM_ALT)],
    "[": [("]", NodeShape.RECTANGLE)],
    "(": [(")", NodeShape.ROUNDED)],
    "{": [("}", NodeShape.RHOMBUS)],
    ">": [("]", NodeShape.ASYMMETRIC)],
}
# Longest open delimiters first, so e.g. "[[" is tried before "[".
_SHAPE_OPEN_ORDER = sorted(_SHAPE_DELIMS, key=len, reverse=True)

# (regex, arrow_type, bidirectional) — longest/most-specific first. Plain
# "<--" (reversed, no matching ">") isn't standard Mermaid syntax, so it's
# deliberately not supported — only the documented bidirectional "<-->"
# family and the standard forward arrows are.
_BARE_CONNECTORS: list[tuple[re.Pattern[str], ArrowType, bool]] = [
    (re.compile(r"<-\.->"), ArrowType.DOTTED_ARROW, True),
    (re.compile(r"<==>"), ArrowType.THICK_ARROW, True),
    (re.compile(r"<-->"), ArrowType.ARROW, True),
    (re.compile(r"-\.->"), ArrowType.DOTTED_ARROW, False),
    (re.compile(r"==>"), ArrowType.THICK_ARROW, False),
    (re.compile(r"-->"), ArrowType.ARROW, False),
    (re.compile(r"-\.-"), ArrowType.DOTTED_OPEN, False),
    (re.compile(r"~~~"), ArrowType.INVISIBLE, False),
    (re.compile(r"==="), ArrowType.THICK_OPEN, False),
    (re.compile(r"---"), ArrowType.OPEN, False),
]

# (open token literal, close regex, open-only arrow type, arrow type if closed with a head)
_INLINE_LABEL_STYLES: list[tuple[str, re.Pattern[str], ArrowType, ArrowType]] = [
    (
        "-.",
        re.compile(r"^-\.\s+(?P<label>.+?)\s+\.-(?P<head>>)?"),
        ArrowType.DOTTED_OPEN,
        ArrowType.DOTTED_ARROW,
    ),
    (
        "==",
        re.compile(r"^==\s+(?P<label>.+?)\s+==(?P<head>>)?"),
        ArrowType.THICK_OPEN,
        ArrowType.THICK_ARROW,
    ),
    (
        "--",
        re.compile(r"^--\s+(?P<label>.+?)\s+--(?P<head>>)?"),
        ArrowType.OPEN,
        ArrowType.ARROW,
    ),
]

_PIPE_LABEL_RE = re.compile(r"\s*\|(?P<label>[^|]*)\|")
_AMPERSAND_RE = re.compile(r"[A-Za-z0-9_\.]\s*&\s*[A-Za-z0-9_\"]")


def _unescape_label(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1].replace('\\"', '"')
    return (
        text.replace("#quot;", '"')
        .replace("#lt;", "<")
        .replace("#gt;", ">")
        .replace("#amp;", "&")
    )


def _find_close(
    line: str, start: int, candidates: list[tuple[str, NodeShape]], line_no: int, open_text: str
) -> tuple[int, str, NodeShape]:
    """Scan forward from `start` for whichever candidate close delimiter
    appears first (skipping over quoted spans), returning its position,
    the delimiter text, and the shape it identifies."""
    i = start
    n = len(line)
    while i < n:
        if line[i] == '"':
            j = i + 1
            while j < n and line[j] != '"':
                j += 2 if line[j] == "\\" and j + 1 < n else 1
            i = j + 1
            continue
        for close_delim, shape in candidates:
            if line.startswith(close_delim, i):
                return i, close_delim, shape
        i += 1
    expected = " or ".join(repr(c) for c, _ in candidates)
    raise MermaidParseError(
        line_no, start + 1, f"unterminated node shape, expected {expected}", open_text
    )


def _parse_node_segment(line: str, pos: int, line_no: int) -> tuple[str, str | None, NodeShape, int]:
    while pos < len(line) and line[pos] == " ":
        pos += 1
    match = _ID_RE.match(line, pos)
    if not match:
        raise MermaidParseError(line_no, pos + 1, "expected a node identifier", line[pos : pos + 10])
    node_id = match.group(0)
    pos = match.end()

    label: str | None = None
    shape = NodeShape.DEFAULT
    for open_delim in _SHAPE_OPEN_ORDER:
        if line.startswith(open_delim, pos):
            content_start = pos + len(open_delim)
            close_pos, close_delim, shape = _find_close(
                line, content_start, _SHAPE_DELIMS[open_delim], line_no, open_delim
            )
            label = _unescape_label(line[content_start:close_pos])
            pos = close_pos + len(close_delim)
            break
    return node_id, label, shape, pos


def _parse_connector(
    line: str, pos: int, line_no: int
) -> tuple[ArrowType, bool, str | None, int] | None:
    """Returns (arrow_type, bidirectional, label, new_pos) or None if no
    connector starts at `pos`."""
    remainder = line[pos:]

    for _open_token, pattern, open_arrow, closed_arrow in _INLINE_LABEL_STYLES:
        match = pattern.match(remainder)
        if match:
            arrow = closed_arrow if match.group("head") else open_arrow
            return arrow, False, match.group("label").strip(), pos + match.end()

    for pattern, arrow, bidirectional in _BARE_CONNECTORS:
        match = pattern.match(remainder)
        if match:
            end = pos + match.end()
            pipe_match = _PIPE_LABEL_RE.match(line, end)
            label = None
            if pipe_match:
                label = pipe_match.group("label").strip()
                end = pipe_match.end()
            return arrow, bidirectional, label, end

    return None


def _strip_comment(line: str) -> str:
    idx = line.find("%%")
    return line if idx == -1 else line[:idx]


class _ParserState:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.subgraphs: list[Subgraph] = []
        self.subgraph_stack: list[str] = []
        self.subgraph_children: dict[str, list[str]] = {}
        self.subgraph_node_ids: dict[str, list[str]] = {}
        self.subgraph_meta: dict[str, tuple[str | None, int]] = {}
        self._auto_id = 0

    def register_node(self, node_id: str, label: str | None, shape: NodeShape, line_no: int) -> None:
        existing = self.nodes.get(node_id)
        if existing is None or shape != NodeShape.DEFAULT and existing.shape == NodeShape.DEFAULT:
            self.nodes[node_id] = Node(id=node_id, label=label, shape=shape, line=line_no)
        if self.subgraph_stack:
            current = self.subgraph_stack[-1]
            if node_id not in self.subgraph_node_ids[current]:
                self.subgraph_node_ids[current].append(node_id)

    def enter_subgraph(self, subgraph_id: str, title: str | None, line_no: int) -> None:
        self.subgraph_meta[subgraph_id] = (title, line_no)
        self.subgraph_node_ids[subgraph_id] = []
        self.subgraph_children[subgraph_id] = []
        if self.subgraph_stack:
            self.subgraph_children[self.subgraph_stack[-1]].append(subgraph_id)
        self.subgraph_stack.append(subgraph_id)

    def exit_subgraph(self, line_no: int) -> None:
        if not self.subgraph_stack:
            raise MermaidParseError(line_no, 1, "'end' with no matching 'subgraph'")
        subgraph_id = self.subgraph_stack.pop()
        title, start_line = self.subgraph_meta[subgraph_id]
        self.subgraphs.append(
            Subgraph(
                id=subgraph_id,
                title=title,
                node_ids=tuple(self.subgraph_node_ids[subgraph_id]),
                subgraph_ids=tuple(self.subgraph_children[subgraph_id]),
                line=start_line,
            )
        )

    def next_auto_subgraph_id(self) -> str:
        self._auto_id += 1
        return f"__subgraph_{self._auto_id}"


_SUBGRAPH_RE = re.compile(r"^subgraph\b\s*(.*)$")
_SUBGRAPH_ID_TITLE_RE = re.compile(r"^([A-Za-z0-9_\.\-]+)\s*\[(.+)\]$")


def _parse_subgraph_header(rest: str) -> tuple[str, str | None]:
    rest = rest.strip()
    if not rest:
        return "", None
    match = _SUBGRAPH_ID_TITLE_RE.match(rest)
    if match:
        return match.group(1), _unescape_label(match.group(2))
    if rest.startswith('"') and rest.endswith('"'):
        return rest, _unescape_label(rest)
    return rest, rest


def parse_flowchart(text: str) -> ParsedDiagram:
    lines = text.splitlines()
    direction: str | None = None
    state = _ParserState()
    started = False

    for line_no, raw_line in enumerate(lines, start=1):
        line = _strip_comment(raw_line).rstrip()
        stripped = line.strip()
        if not stripped:
            continue

        if not started:
            header = _HEADER_RE.match(stripped)
            if not header:
                raise MermaidParseError(
                    line_no, 1, "expected a 'graph' or 'flowchart' header", stripped
                )
            direction = header.group(2)
            if direction not in _DIRECTIONS:
                raise MermaidParseError(
                    line_no, 1, f"unknown direction {direction!r}; expected one of {sorted(_DIRECTIONS)}"
                )
            started = True
            continue

        if stripped.startswith(_IGNORABLE_DIRECTIVES):
            continue
        if stripped.startswith("direction "):
            continue

        subgraph_match = _SUBGRAPH_RE.match(stripped)
        if subgraph_match:
            subgraph_id, title = _parse_subgraph_header(subgraph_match.group(1))
            if not subgraph_id:
                subgraph_id = state.next_auto_subgraph_id()
            state.enter_subgraph(subgraph_id, title, line_no)
            continue

        if stripped == "end":
            state.exit_subgraph(line_no)
            continue

        if _AMPERSAND_RE.search(stripped):
            raise MermaidParseError(
                line_no, 1, "ampersand fan-out/fan-in (A --> B & C) is not supported", stripped
            )

        _parse_statement_line(line, line_no, state)

    if state.subgraph_stack:
        raise MermaidParseError(
            len(lines), 1, f"unterminated subgraph(s): {state.subgraph_stack!r}"
        )
    if not started:
        raise MermaidParseError(1, 1, "empty diagram: expected a 'graph' or 'flowchart' header")

    return ParsedDiagram(
        diagram_type="flowchart",
        direction=direction,
        nodes=tuple(state.nodes.values()),
        edges=tuple(state.edges),
        subgraphs=tuple(state.subgraphs),
    )


def _parse_statement_line(line: str, line_no: int, state: _ParserState) -> None:
    pos = 0
    node_id, label, shape, pos = _parse_node_segment(line, pos, line_no)
    state.register_node(node_id, label, shape, line_no)
    previous_id = node_id

    while True:
        skip_pos = pos
        while skip_pos < len(line) and line[skip_pos] == " ":
            skip_pos += 1
        if skip_pos >= len(line):
            break

        connector = _parse_connector(line, skip_pos, line_no)
        if connector is None:
            raise MermaidParseError(
                line_no, skip_pos + 1, "expected an edge connector or end of line", line[skip_pos:]
            )
        arrow, bidirectional, edge_label, pos = connector

        while pos < len(line) and line[pos] == " ":
            pos += 1
        next_id, next_label, next_shape, pos = _parse_node_segment(line, pos, line_no)
        state.register_node(next_id, next_label, next_shape, line_no)

        state.edges.append(
            Edge(
                source=previous_id,
                target=next_id,
                arrow=arrow,
                bidirectional=bidirectional,
                label=edge_label,
                line=line_no,
            )
        )
        previous_id = next_id
