from fastapi import APIRouter
from pydantic import BaseModel

from app.services.mermaid.errors import MermaidParseError
from app.services.mermaid.models import Edge, Node, ParsedDiagram, Subgraph
from app.services.mermaid.parser import parse_diagram
from app.services.mermaid.renderer import render_flowchart

router = APIRouter(prefix="/mermaid", tags=["mermaid"])


class ParseMermaidRequest(BaseModel):
    source: str


class NodeOut(BaseModel):
    id: str
    label: str | None
    shape: str
    line: int


class EdgeOut(BaseModel):
    source: str
    target: str
    arrow: str
    bidirectional: bool
    label: str | None
    line: int


class SubgraphOut(BaseModel):
    id: str
    title: str | None
    node_ids: list[str]
    subgraph_ids: list[str]
    line: int


class ParseMermaidResponse(BaseModel):
    ok: bool
    diagram_type: str | None = None
    direction: str | None = None
    nodes: list[NodeOut] = []
    edges: list[EdgeOut] = []
    subgraphs: list[SubgraphOut] = []
    normalized_source: str | None = None
    error: str | None = None
    error_line: int | None = None
    error_column: int | None = None


def _to_node_out(node: Node) -> NodeOut:
    return NodeOut(id=node.id, label=node.label, shape=node.shape.value, line=node.line)


def _to_edge_out(edge: Edge) -> EdgeOut:
    return EdgeOut(
        source=edge.source,
        target=edge.target,
        arrow=edge.arrow.value,
        bidirectional=edge.bidirectional,
        label=edge.label,
        line=edge.line,
    )


def _to_subgraph_out(subgraph: Subgraph) -> SubgraphOut:
    return SubgraphOut(
        id=subgraph.id,
        title=subgraph.title,
        node_ids=list(subgraph.node_ids),
        subgraph_ids=list(subgraph.subgraph_ids),
        line=subgraph.line,
    )


@router.post("/parse", response_model=ParseMermaidResponse)
async def parse_mermaid(body: ParseMermaidRequest) -> ParseMermaidResponse:
    try:
        diagram: ParsedDiagram = parse_diagram(body.source)
    except MermaidParseError as exc:
        return ParseMermaidResponse(
            ok=False, error=exc.message, error_line=exc.line, error_column=exc.column
        )

    return ParseMermaidResponse(
        ok=True,
        diagram_type=diagram.diagram_type,
        direction=diagram.direction,
        nodes=[_to_node_out(n) for n in diagram.nodes],
        edges=[_to_edge_out(e) for e in diagram.edges],
        subgraphs=[_to_subgraph_out(s) for s in diagram.subgraphs],
        normalized_source=render_flowchart(diagram),
    )
