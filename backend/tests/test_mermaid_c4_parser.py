import pytest

from app.services.mermaid.c4_parser import parse_c4
from app.services.mermaid.errors import MermaidParseError

REAL_EXAMPLE = """C4Context
    title System Context diagram for Internet Banking System
    Enterprise_Boundary(b0, "BankBoundary0") {
        Person(customerA, "Banking Customer A", "A customer of the bank.")
        System(SystemAA, "Internet Banking System", "Allows customers to view information.")
        System_Ext(SystemE, "E-mail system", "The internal Microsoft Exchange system")
        Rel(customerA, SystemAA, "Uses")
        Rel(SystemAA, SystemE, "Sends e-mails using", "SMTP")
    }
"""


def test_elements_parsed_as_nodes():
    diagram = parse_c4(REAL_EXAMPLE)
    ids = {n.id for n in diagram.nodes}
    assert ids == {"customerA", "SystemAA", "SystemE"}


def test_element_label_preserves_macro_type_and_description():
    diagram = parse_c4(REAL_EXAMPLE)
    node = next(n for n in diagram.nodes if n.id == "customerA")
    assert node.label == "[Person] Banking Customer A: A customer of the bank."


def test_rel_macros_become_edges():
    diagram = parse_c4(REAL_EXAMPLE)
    pairs = [(e.source, e.target, e.label) for e in diagram.edges]
    assert ("customerA", "SystemAA", "Uses") in pairs
    assert ("SystemAA", "SystemE", "Sends e-mails using") in pairs


def test_boundary_becomes_subgraph_with_member_nodes():
    diagram = parse_c4(REAL_EXAMPLE)
    assert len(diagram.subgraphs) == 1
    boundary = diagram.subgraphs[0]
    assert boundary.id == "b0"
    assert boundary.title == "BankBoundary0"
    assert set(boundary.node_ids) == {"customerA", "SystemAA", "SystemE"}


def test_bi_rel_is_bidirectional():
    src = 'C4Context\n  Person(a, "A")\n  Person(b, "B")\n  BiRel(a, b, "Talks to")\n'
    diagram = parse_c4(src)
    assert diagram.edges[0].bidirectional is True


def test_rel_back_swaps_source_and_target():
    src = 'C4Context\n  Person(a, "A")\n  Person(b, "B")\n  Rel_Back(a, b, "Responds to")\n'
    diagram = parse_c4(src)
    assert diagram.edges[0].source == "b"
    assert diagram.edges[0].target == "a"


def test_nested_boundaries():
    src = """C4Context
    System_Boundary(outer, "Outer") {
        Person(a, "A")
        Container_Boundary(inner, "Inner") {
            System(b, "B")
        }
    }
    """
    diagram = parse_c4(src)
    by_id = {s.id: s for s in diagram.subgraphs}
    assert by_id["inner"].node_ids == ("b",)
    assert by_id["outer"].node_ids == ("a",)
    assert by_id["outer"].subgraph_ids == ("inner",)


def test_title_and_style_directives_are_ignored():
    src = """C4Context
    title Some Title
    Person(a, "A")
    UpdateElementStyle(a, $fontColor="red")
    """
    diagram = parse_c4(src)
    assert len(diagram.nodes) == 1


def test_c4container_header_accepted():
    diagram = parse_c4('C4Container\n  Person(a, "A")\n')
    assert diagram.diagram_type == "c4context"


def test_missing_header_raises():
    with pytest.raises(MermaidParseError, match="expected a C4 diagram header"):
        parse_c4('Person(a, "A")\n')


def test_boundary_without_open_brace_raises():
    with pytest.raises(MermaidParseError, match="must open a block"):
        parse_c4('C4Context\n  System_Boundary(b0, "Zone")\n')


def test_unterminated_boundary_raises():
    with pytest.raises(MermaidParseError, match="unterminated boundary"):
        parse_c4('C4Context\n  System_Boundary(b0, "Zone") {\n    Person(a, "A")\n')


def test_close_brace_without_boundary_raises():
    with pytest.raises(MermaidParseError, match="no matching boundary"):
        parse_c4("C4Context\n  }\n")


def test_unrecognized_macro_raises():
    with pytest.raises(MermaidParseError, match="unrecognized C4 macro"):
        parse_c4('C4Context\n  Frobnicate(a, "A")\n')


def test_rel_missing_target_raises():
    with pytest.raises(MermaidParseError, match="requires source and target"):
        parse_c4("C4Context\n  Rel(a)\n")
