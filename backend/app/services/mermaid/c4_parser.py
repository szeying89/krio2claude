"""Best-effort C4Context/C4Container/C4Component parser.

C4 diagrams are structurally simple compared to flowcharts — each
statement is essentially a function-call-like macro on its own line — but
use an entirely different grammar (element macros, boundary blocks closed
with `}` rather than `end`, `Rel(...)` relationship macros) rather than
Mermaid's arrow syntax. Reused here onto the same Node/Edge/Subgraph model
so downstream code doesn't need to special-case diagram type: boundary
macros become Subgraphs (candidate trust zones, same as flowchart
subgraphs), element macros become Nodes, and Rel-family macros become
Edges.

Element "shape" carries no meaning in C4 (there is no bracket-shape
syntax), so every C4 node uses NodeShape.DEFAULT; the macro name itself
(Person, System, SystemDb, Container, ...) is preserved as a label prefix
so element-type information isn't lost.
"""

from __future__ import annotations

import re

from app.services.mermaid.errors import MermaidParseError
from app.services.mermaid.models import ArrowType, Edge, Node, NodeShape, ParsedDiagram, Subgraph

_HEADER_RE = re.compile(r"^(C4Context|C4Container|C4Component|C4Dynamic|C4Deployment)\s*$")

_ELEMENT_MACROS = {
    "Person",
    "Person_Ext",
    "System",
    "System_Ext",
    "SystemDb",
    "SystemDb_Ext",
    "SystemQueue",
    "SystemQueue_Ext",
    "Container",
    "Container_Ext",
    "ContainerDb",
    "ContainerDb_Ext",
    "ContainerQueue",
    "ContainerQueue_Ext",
    "Component",
    "Component_Ext",
    "ComponentDb",
    "ComponentQueue",
}
_BOUNDARY_MACROS = {
    "Enterprise_Boundary",
    "System_Boundary",
    "Container_Boundary",
    "Boundary",
}
_REL_MACROS = {
    "Rel",
    "BiRel",
    "Rel_Back",
    "Rel_U",
    "Rel_D",
    "Rel_L",
    "Rel_R",
    "Rel_Up",
    "Rel_Down",
    "Rel_Left",
    "Rel_Right",
    "RelIndex",
}
_IGNORABLE_PREFIXES = (
    "title ",
    "UpdateElementStyle(",
    "UpdateRelStyle(",
    "UpdateLayoutConfig(",
    "UpdateBoundaryStyle(",
)

_ARGS_RE = re.compile(r"^(\w+)\((.*)\)\s*(\{)?\s*$")


def _split_args(raw: str) -> list[str]:
    """Split macro arguments on top-level commas, respecting quoted strings
    (a quoted argument may itself contain commas, e.g. a description)."""
    args: list[str] = []
    current: list[str] = []
    in_quotes = False
    i = 0
    while i < len(raw):
        ch = raw[i]
        if ch == '"' and (i == 0 or raw[i - 1] != "\\"):
            in_quotes = not in_quotes
            current.append(ch)
        elif ch == "," and not in_quotes:
            args.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    if current:
        args.append("".join(current).strip())
    return [_unquote(a) for a in args]


def _unquote(text: str) -> str:
    text = text.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        return text[1:-1].replace('\\"', '"')
    return text


def parse_c4(text: str) -> ParsedDiagram:
    lines = text.splitlines()
    nodes: dict[str, Node] = {}
    edges: list[Edge] = []
    subgraphs: list[Subgraph] = []
    boundary_stack: list[str] = []
    boundary_node_ids: dict[str, list[str]] = {}
    boundary_child_ids: dict[str, list[str]] = {}
    boundary_meta: dict[str, tuple[str | None, int]] = {}
    started = False

    def register_node(node_id: str, label: str, line_no: int) -> None:
        if node_id not in nodes:
            nodes[node_id] = Node(id=node_id, label=label, shape=NodeShape.DEFAULT, line=line_no)
        if boundary_stack:
            boundary_node_ids[boundary_stack[-1]].append(node_id)

    for line_no, raw_line in enumerate(lines, start=1):
        idx = raw_line.find("%%")
        line = (raw_line if idx == -1 else raw_line[:idx]).strip()
        if not line:
            continue

        if not started:
            if not _HEADER_RE.match(line):
                raise MermaidParseError(
                    line_no, 1, "expected a C4 diagram header (e.g. 'C4Context')", line
                )
            started = True
            continue

        if line == "}":
            if not boundary_stack:
                raise MermaidParseError(line_no, 1, "'}' with no matching boundary macro")
            boundary_id = boundary_stack.pop()
            title, start_line = boundary_meta[boundary_id]
            subgraphs.append(
                Subgraph(
                    id=boundary_id,
                    title=title,
                    node_ids=tuple(boundary_node_ids[boundary_id]),
                    subgraph_ids=tuple(boundary_child_ids[boundary_id]),
                    line=start_line,
                )
            )
            continue

        if line.startswith(_IGNORABLE_PREFIXES):
            continue

        match = _ARGS_RE.match(line)
        if not match:
            raise MermaidParseError(line_no, 1, "unrecognized C4 statement", line)
        macro, raw_args, opens_block = match.groups()
        args = _split_args(raw_args)

        if macro in _ELEMENT_MACROS:
            if not args:
                raise MermaidParseError(line_no, 1, f"{macro}(...) requires an id", line)
            node_id = args[0]
            display = args[1] if len(args) > 1 else node_id
            description = args[2] if len(args) > 2 else ""
            label = f"[{macro}] {display}" + (f": {description}" if description else "")
            register_node(node_id, label, line_no)
        elif macro in _BOUNDARY_MACROS:
            if not opens_block:
                raise MermaidParseError(
                    line_no, 1, f"{macro}(...) must open a block with '{{'", line
                )
            if not args:
                raise MermaidParseError(line_no, 1, f"{macro}(...) requires an id", line)
            boundary_id = args[0]
            title = args[1] if len(args) > 1 else None
            boundary_meta[boundary_id] = (title, line_no)
            boundary_node_ids[boundary_id] = []
            boundary_child_ids[boundary_id] = []
            if boundary_stack:
                boundary_child_ids[boundary_stack[-1]].append(boundary_id)
            boundary_stack.append(boundary_id)
        elif macro in _REL_MACROS:
            if len(args) < 2:
                raise MermaidParseError(line_no, 1, f"{macro}(...) requires source and target", line)
            source, target = args[0], args[1]
            rel_label = args[2] if len(args) > 2 else None
            if macro == "Rel_Back":
                source, target = target, source
            edges.append(
                Edge(
                    source=source,
                    target=target,
                    arrow=ArrowType.ARROW,
                    bidirectional=(macro == "BiRel"),
                    label=rel_label,
                    line=line_no,
                )
            )
        else:
            raise MermaidParseError(line_no, 1, f"unrecognized C4 macro {macro!r}", line)

    if boundary_stack:
        raise MermaidParseError(len(lines), 1, f"unterminated boundary block(s): {boundary_stack!r}")
    if not started:
        raise MermaidParseError(1, 1, "empty diagram: expected a C4 diagram header")

    return ParsedDiagram(
        diagram_type="c4context",
        direction=None,
        nodes=tuple(nodes.values()),
        edges=tuple(edges),
        subgraphs=tuple(subgraphs),
    )
