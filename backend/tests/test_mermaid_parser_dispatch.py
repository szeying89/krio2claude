import pytest

from app.services.mermaid.errors import MermaidParseError
from app.services.mermaid.parser import parse_diagram


def test_dispatches_to_flowchart_parser():
    diagram = parse_diagram("graph TD\n  A --> B\n")
    assert diagram.diagram_type == "flowchart"


def test_dispatches_to_c4_parser():
    diagram = parse_diagram('C4Context\n  Person(a, "A")\n')
    assert diagram.diagram_type == "c4context"


def test_leading_comments_and_blank_lines_are_skipped_before_dispatch():
    diagram = parse_diagram("\n%% a comment\n\ngraph LR\n  A --> B\n")
    assert diagram.diagram_type == "flowchart"


def test_unrecognized_diagram_type_raises():
    with pytest.raises(MermaidParseError, match="unrecognized diagram type"):
        parse_diagram("sequenceDiagram\n  Alice->>Bob: Hello\n")


def test_empty_input_raises():
    with pytest.raises(MermaidParseError, match="empty diagram"):
        parse_diagram("   \n\n  ")
