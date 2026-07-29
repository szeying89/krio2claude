import pytest

from app.services.mermaid.errors import MermaidParseError
from app.services.mermaid.flowchart_parser import parse_flowchart
from app.services.mermaid.models import ArrowType, NodeShape

# --- directions ---


@pytest.mark.parametrize("direction", ["TD", "TB", "BT", "RL", "LR"])
def test_all_directions_parsed(direction):
    diagram = parse_flowchart(f"graph {direction}\n  A --> B\n")
    assert diagram.direction == direction


def test_flowchart_keyword_accepted_same_as_graph():
    diagram = parse_flowchart("flowchart TD\n  A --> B\n")
    assert diagram.direction == "TD"


def test_unknown_direction_rejected():
    with pytest.raises(MermaidParseError, match="unknown direction"):
        parse_flowchart("graph ZZ\n  A --> B\n")


# --- node shapes ---

SHAPE_CASES = [
    ("A[Rect]", NodeShape.RECTANGLE, "Rect"),
    ("A(Round)", NodeShape.ROUNDED, "Round"),
    ("A([Stadium])", NodeShape.STADIUM, "Stadium"),
    ("A[[Subroutine]]", NodeShape.SUBROUTINE, "Subroutine"),
    ("A[(Cylinder)]", NodeShape.CYLINDER, "Cylinder"),
    ("A((Circle))", NodeShape.CIRCLE, "Circle"),
    ("A(((Double)))", NodeShape.DOUBLE_CIRCLE, "Double"),
    ("A{Rhombus}", NodeShape.RHOMBUS, "Rhombus"),
    ("A{{Hexagon}}", NodeShape.HEXAGON, "Hexagon"),
    ("A>Flag]", NodeShape.ASYMMETRIC, "Flag"),
    ("A[/Parallelogram/]", NodeShape.PARALLELOGRAM, "Parallelogram"),
    ("A[\\ParallelogramAlt\\]", NodeShape.PARALLELOGRAM_ALT, "ParallelogramAlt"),
    ("A[/Trapezoid\\]", NodeShape.TRAPEZOID, "Trapezoid"),
    ("A[\\TrapezoidAlt/]", NodeShape.TRAPEZOID_ALT, "TrapezoidAlt"),
]


@pytest.mark.parametrize("segment,shape,label", SHAPE_CASES)
def test_every_node_shape(segment, shape, label):
    diagram = parse_flowchart(f"graph TD\n  {segment} --> B\n")
    node = next(n for n in diagram.nodes if n.id == "A")
    assert node.shape == shape
    assert node.label == label


def test_bare_node_has_default_shape_and_no_label():
    diagram = parse_flowchart("graph TD\n  A --> B\n")
    node = next(n for n in diagram.nodes if n.id == "A")
    assert node.shape == NodeShape.DEFAULT
    assert node.label is None


def test_first_shaped_occurrence_wins_over_later_bare_reference():
    diagram = parse_flowchart("graph TD\n  A[Shaped] --> B\n  C --> A\n")
    node = next(n for n in diagram.nodes if n.id == "A")
    assert node.shape == NodeShape.RECTANGLE
    assert node.label == "Shaped"


# --- edges / arrow types ---

ARROW_CASES = [
    ("A --- B", ArrowType.OPEN, False, None),
    ("A --> B", ArrowType.ARROW, False, None),
    ("A -.- B", ArrowType.DOTTED_OPEN, False, None),
    ("A -.-> B", ArrowType.DOTTED_ARROW, False, None),
    ("A === B", ArrowType.THICK_OPEN, False, None),
    ("A ==> B", ArrowType.THICK_ARROW, False, None),
    ("A ~~~ B", ArrowType.INVISIBLE, False, None),
    ("A <--> B", ArrowType.ARROW, True, None),
    ("A <-.-> B", ArrowType.DOTTED_ARROW, True, None),
    ("A <==> B", ArrowType.THICK_ARROW, True, None),
    ("A -->|label| B", ArrowType.ARROW, False, "label"),
    ("A --> |label| B", ArrowType.ARROW, False, "label"),
    ("A -- inline text --> B", ArrowType.ARROW, False, "inline text"),
    ("A -. dotted text .-> B", ArrowType.DOTTED_ARROW, False, "dotted text"),
    ("A == thick text ==> B", ArrowType.THICK_ARROW, False, "thick text"),
]


@pytest.mark.parametrize("statement,arrow,bidi,label", ARROW_CASES)
def test_every_arrow_type(statement, arrow, bidi, label):
    diagram = parse_flowchart(f"graph TD\n  {statement}\n")
    assert len(diagram.edges) == 1
    edge = diagram.edges[0]
    assert edge.source == "A"
    assert edge.target == "B"
    assert edge.arrow == arrow
    assert edge.bidirectional == bidi
    assert edge.label == label


def test_chained_edges_on_one_line():
    diagram = parse_flowchart("graph TD\n  A --> B --> C\n")
    pairs = [(e.source, e.target) for e in diagram.edges]
    assert pairs == [("A", "B"), ("B", "C")]


def test_self_loop():
    diagram = parse_flowchart("graph LR\n  A --> A\n")
    assert diagram.edges[0].source == "A"
    assert diagram.edges[0].target == "A"


def test_ampersand_fan_out_explicitly_rejected():
    with pytest.raises(MermaidParseError, match="ampersand fan-out"):
        parse_flowchart("graph TD\n  A --> B & C\n")


# --- subgraphs ---


def test_nested_subgraphs_with_ids_and_titles():
    src = """graph TD
    subgraph outer[Outer Zone]
        A --> B
        subgraph inner[Inner Zone]
            C --> D
        end
    end
    """
    diagram = parse_flowchart(src)
    by_id = {s.id: s for s in diagram.subgraphs}
    assert by_id["inner"].title == "Inner Zone"
    assert by_id["inner"].node_ids == ("C", "D")
    assert by_id["outer"].title == "Outer Zone"
    assert by_id["outer"].node_ids == ("A", "B")
    assert by_id["outer"].subgraph_ids == ("inner",)


def test_subgraph_without_explicit_id_gets_title_as_id():
    diagram = parse_flowchart("graph TD\n  subgraph Zone1\n    A --> B\n  end\n")
    assert diagram.subgraphs[0].id == "Zone1"
    assert diagram.subgraphs[0].title == "Zone1"


def test_unterminated_subgraph_raises():
    with pytest.raises(MermaidParseError, match="unterminated subgraph"):
        parse_flowchart("graph TD\n  subgraph Zone1\n    A --> B\n")


def test_end_without_subgraph_raises():
    with pytest.raises(MermaidParseError, match="no matching 'subgraph'"):
        parse_flowchart("graph TD\n  end\n")


# --- quoted / escaped labels ---


def test_quoted_label_with_escaped_quotes_and_commas():
    diagram = parse_flowchart('graph LR\n  A["Quoted \\"inner\\" with, commas"] --> B\n')
    node = next(n for n in diagram.nodes if n.id == "A")
    assert node.label == 'Quoted "inner" with, commas'


def test_html_entity_escapes_in_label():
    diagram = parse_flowchart("graph LR\n  A[Value #lt; 5 #amp; #quot;ok#quot;] --> B\n")
    node = next(n for n in diagram.nodes if n.id == "A")
    assert node.label == 'Value < 5 & "ok"'


def test_bracket_characters_inside_quoted_label_do_not_confuse_shape_boundary():
    diagram = parse_flowchart('graph LR\n  A["has ] and [ inside"] --> B\n')
    node = next(n for n in diagram.nodes if n.id == "A")
    assert node.label == "has ] and [ inside"


# --- malformed input diagnostics ---


def test_missing_header_raises_with_location():
    with pytest.raises(MermaidParseError) as excinfo:
        parse_flowchart("A --> B\n")
    assert excinfo.value.line == 1


def test_unterminated_shape_raises_with_location():
    with pytest.raises(MermaidParseError, match="unterminated node shape"):
        parse_flowchart("graph TD\n  A[Unterminated --> B\n")


def test_dangling_connector_raises():
    with pytest.raises(MermaidParseError):
        parse_flowchart("graph TD\n  A -->\n")


def test_empty_diagram_raises():
    with pytest.raises(MermaidParseError, match="empty diagram"):
        parse_flowchart("")


def test_comments_are_ignored():
    diagram = parse_flowchart("graph TD\n  %% this is a comment\n  A --> B %% trailing comment\n")
    assert len(diagram.edges) == 1


def test_style_and_class_directives_are_tolerated():
    src = """graph TD
    A --> B
    style A fill:#f9f
    classDef important fill:#f96
    class A important
    click A "https://example.com"
    linkStyle 0 stroke:#ff0000
    """
    diagram = parse_flowchart(src)
    assert len(diagram.nodes) == 2
    assert len(diagram.edges) == 1
