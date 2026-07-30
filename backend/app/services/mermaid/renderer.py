"""Renders a ParsedDiagram back to canonical Mermaid flowchart syntax.

Used for the "normalised re-render" demo: regardless of whether the source
was a flowchart or a C4 diagram, the re-render is always canonical
flowchart syntax — a useful normalization step in its own right, not just
a display convenience.
"""

from __future__ import annotations

from app.services.mermaid.models import ArrowType, Edge, Node, NodeShape, ParsedDiagram, Subgraph

_SHAPE_WRAP: dict[NodeShape, tuple[str, str]] = {
    NodeShape.RECTANGLE: ("[", "]"),
    NodeShape.ROUNDED: ("(", ")"),
    NodeShape.STADIUM: ("([", "])"),
    NodeShape.SUBROUTINE: ("[[", "]]"),
    NodeShape.CYLINDER: ("[(", ")]"),
    NodeShape.CIRCLE: ("((", "))"),
    NodeShape.DOUBLE_CIRCLE: ("(((", ")))"),
    NodeShape.RHOMBUS: ("{", "}"),
    NodeShape.HEXAGON: ("{{", "}}"),
    NodeShape.ASYMMETRIC: (">", "]"),
    NodeShape.PARALLELOGRAM: ("[/", "/]"),
    NodeShape.PARALLELOGRAM_ALT: ("[\\", "\\]"),
    NodeShape.TRAPEZOID: ("[/", "\\]"),
    NodeShape.TRAPEZOID_ALT: ("[\\", "/]"),
}

_ARROW_TEXT: dict[ArrowType, str] = {
    ArrowType.OPEN: "---",
    ArrowType.ARROW: "-->",
    ArrowType.DOTTED_OPEN: "-.-",
    ArrowType.DOTTED_ARROW: "-.->",
    ArrowType.THICK_OPEN: "===",
    ArrowType.THICK_ARROW: "==>",
    ArrowType.INVISIBLE: "~~~",
}


def _quote_if_needed(label: str) -> str:
    if any(ch in label for ch in "\"[](){}|"):
        return '"' + label.replace('"', '\\"') + '"'
    return label


def _render_node(node: Node) -> str:
    if node.shape == NodeShape.DEFAULT or node.label is None:
        return node.id
    open_wrap, close_wrap = _SHAPE_WRAP[node.shape]
    return f"{node.id}{open_wrap}{_quote_if_needed(node.label)}{close_wrap}"


def _render_edge(edge: Edge) -> str:
    arrow_text = _ARROW_TEXT[edge.arrow]
    if edge.bidirectional:
        arrow_text = "<" + arrow_text
    label_part = f"|{edge.label}|" if edge.label else ""
    return f"    {edge.source} {arrow_text}{label_part} {edge.target}"


def render_flowchart(diagram: ParsedDiagram, indent: str = "    ") -> str:
    lines = [f"graph {diagram.direction or 'TD'}"]

    subgraph_by_id = {s.id: s for s in diagram.subgraphs}
    child_ids = {child for s in diagram.subgraphs for child in s.subgraph_ids}
    root_subgraphs = [s for s in diagram.subgraphs if s.id not in child_ids]
    nodes_in_subgraphs = {nid for s in diagram.subgraphs for nid in s.node_ids}

    def render_subgraph(subgraph: Subgraph, depth: int) -> None:
        pad = indent * depth
        header = f"{pad}subgraph {subgraph.id}"
        if subgraph.title and subgraph.title != subgraph.id:
            header += f"[{_quote_if_needed(subgraph.title)}]"
        lines.append(header)
        for node_id in subgraph.node_ids:
            node = nodes_by_id.get(node_id)
            if node is not None:
                lines.append(f"{pad}{indent}{_render_node(node)}")
        for child_id in subgraph.subgraph_ids:
            render_subgraph(subgraph_by_id[child_id], depth + 1)
        lines.append(f"{pad}end")

    nodes_by_id = {n.id: n for n in diagram.nodes}
    for subgraph in root_subgraphs:
        render_subgraph(subgraph, 1)

    for node in diagram.nodes:
        if node.id not in nodes_in_subgraphs:
            lines.append(f"{indent}{_render_node(node)}")

    for edge in diagram.edges:
        lines.append(_render_edge(edge))

    return "\n".join(lines) + "\n"
