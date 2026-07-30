from app.services.mermaid.parser import parse_diagram
from app.services.mermaid.renderer import render_flowchart


def test_render_round_trips_topology():
    src = """graph TD
    subgraph Zone1[Trust Zone 1]
        A[Web Server] --> B{Auth Check}
    end
    B -->|OK| C((Database))
    B -->|Fail| D[/Reject/]
"""
    diagram = parse_diagram(src)
    rendered = render_flowchart(diagram)
    reparsed = parse_diagram(rendered)

    assert {n.id for n in diagram.nodes} == {n.id for n in reparsed.nodes}
    assert len(diagram.edges) == len(reparsed.edges)
    assert {s.id for s in diagram.subgraphs} == {s.id for s in reparsed.subgraphs}


def test_render_is_deterministic():
    diagram = parse_diagram("graph LR\n  A[Start] --> B{Check}\n")
    assert render_flowchart(diagram) == render_flowchart(diagram)


def test_render_preserves_node_shapes():
    diagram = parse_diagram("graph TD\n  A((Circle)) --> B[/Parallelogram/]\n")
    rendered = render_flowchart(diagram)
    assert "A((Circle))" in rendered
    assert "B[/Parallelogram/]" in rendered


def test_render_quotes_labels_containing_special_characters():
    diagram = parse_diagram('graph TD\n  A["Has [brackets] inside"] --> B\n')
    rendered = render_flowchart(diagram)
    assert '\\"Has [brackets] inside\\"' in rendered or '"Has [brackets] inside"' in rendered


def test_c4_diagram_renders_as_normalized_flowchart():
    diagram = parse_diagram('C4Context\n  Person(a, "Alice")\n  System(b, "App")\n  Rel(a, b, "Uses")\n')
    rendered = render_flowchart(diagram)
    assert rendered.startswith("graph TD")
    assert "a -->|Uses| b" in rendered
