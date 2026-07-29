"""Parsed-diagram data model shared by the flowchart and C4Context parsers."""

from __future__ import annotations

import enum
from dataclasses import dataclass


class NodeShape(str, enum.Enum):
    DEFAULT = "default"  # bare id reference, no shape declared at this occurrence
    RECTANGLE = "rectangle"  # [text]
    ROUNDED = "rounded"  # (text)
    STADIUM = "stadium"  # ([text])
    SUBROUTINE = "subroutine"  # [[text]]
    CYLINDER = "cylinder"  # [(text)]
    CIRCLE = "circle"  # ((text))
    DOUBLE_CIRCLE = "double_circle"  # (((text)))
    ASYMMETRIC = "asymmetric"  # >text]
    RHOMBUS = "rhombus"  # {text}
    HEXAGON = "hexagon"  # {{text}}
    PARALLELOGRAM = "parallelogram"  # [/text/]
    PARALLELOGRAM_ALT = "parallelogram_alt"  # [\text\]
    TRAPEZOID = "trapezoid"  # [/text\]
    TRAPEZOID_ALT = "trapezoid_alt"  # [\text/]


class ArrowType(str, enum.Enum):
    OPEN = "open"  # ---
    ARROW = "arrow"  # -->
    DOTTED_OPEN = "dotted_open"  # -.-
    DOTTED_ARROW = "dotted_arrow"  # -.->
    THICK_OPEN = "thick_open"  # ===
    THICK_ARROW = "thick_arrow"  # ==>
    INVISIBLE = "invisible"  # ~~~


@dataclass(frozen=True)
class Node:
    id: str
    label: str | None
    shape: NodeShape
    line: int


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    arrow: ArrowType
    bidirectional: bool
    label: str | None
    line: int


@dataclass(frozen=True)
class Subgraph:
    id: str
    title: str | None
    node_ids: tuple[str, ...]
    subgraph_ids: tuple[str, ...]
    line: int


@dataclass(frozen=True)
class ParsedDiagram:
    diagram_type: str  # "flowchart" | "c4context"
    direction: str | None
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    subgraphs: tuple[Subgraph, ...]
