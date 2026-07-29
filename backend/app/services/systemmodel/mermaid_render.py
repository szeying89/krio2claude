"""Render a `SystemModel` to canonical Mermaid flowchart syntax, reusing
Task 6's `ParsedDiagram`/`render_flowchart` rather than templating Mermaid
text by hand — the model becomes the same Node/Edge/Subgraph shape the
parser itself produces, so this output re-parses cleanly.

Deterministic per model version: rendering the same `SystemModel` twice
produces byte-identical output (no dict/set iteration order dependence —
every collection here is the model's own already-ordered lists).
"""

from __future__ import annotations

import re

from app.services.mermaid.models import ArrowType, Edge, Node, NodeShape, ParsedDiagram, Subgraph
from app.services.mermaid.renderer import render_flowchart
from app.services.systemmodel.models import SystemModel

_KIND_SHAPE: dict[str, NodeShape] = {
    "process": NodeShape.RECTANGLE,
    "datastore": NodeShape.CYLINDER,
    "external_entity": NodeShape.CIRCLE,
}


def _mermaid_id(raw_id: str) -> str:
    """Mermaid node/subgraph ids are safest as `[A-Za-z0-9_]` — our own ids
    use hyphens (`component-1`), so translate them for this render only;
    the model's real ids are untouched."""
    return re.sub(r"[^A-Za-z0-9_]", "_", raw_id)


def render_system_model(model: SystemModel) -> str:
    nodes = tuple(
        Node(
            id=_mermaid_id(c.id),
            label=c.name,
            shape=_KIND_SHAPE.get(c.kind, NodeShape.RECTANGLE),
            line=0,
        )
        for c in model.components
    )
    edges = tuple(
        Edge(
            source=_mermaid_id(f.source_id),
            target=_mermaid_id(f.destination_id),
            arrow=ArrowType.ARROW,
            bidirectional=f.bidirectional,
            label=f.name or None,
            line=0,
        )
        for f in model.dataflows
    )
    subgraphs = tuple(
        Subgraph(
            id=_mermaid_id(zone.id),
            title=zone.name,
            node_ids=tuple(
                _mermaid_id(c.id) for c in model.components if c.trust_zone_id == zone.id
            ),
            subgraph_ids=(),
            line=0,
        )
        for zone in model.trust_zones
    )
    diagram = ParsedDiagram(
        diagram_type="flowchart",
        direction="TD",
        nodes=nodes,
        edges=edges,
        subgraphs=subgraphs,
    )
    return render_flowchart(diagram)
