"""The invalidation graph is the single mechanism behind three previously
separate "re-run only what's affected" requirements: a clarification
answered (Task 8), a review item accepted (Task 21), and a threat-intel
revision attached (Task 19). All three are exercised here via the same
`compute_affected` code path, driven only by which artifact types changed.
"""

from app.orchestrator.contracts import AgentSpec
from app.orchestrator.invalidation import InvalidationGraph
from app.orchestrator.registry import AgentRegistry


def _noop_handler(ctx):
    return {}


def build_pipeline_registry() -> AgentRegistry:
    registry = AgentRegistry()
    registry.register(
        AgentSpec("model_building", ("design_doc",), ("system_model",), _noop_handler)
    )
    registry.register(
        AgentSpec(
            "enumeration",
            ("system_model",),
            ("adjudicated_threats", "attack_paths"),
            _noop_handler,
        )
    )
    registry.register(
        AgentSpec(
            "risk_mitigation",
            ("adjudicated_threats", "attack_paths"),
            ("risk_register", "mitigations"),
            _noop_handler,
        )
    )
    registry.register(
        AgentSpec(
            "assurance",
            ("risk_register", "mitigations"),
            ("confidence", "review_items"),
            _noop_handler,
        )
    )
    registry.register(
        AgentSpec("intel", ("intel_article",), ("adjudicated_threats",), _noop_handler)
    )
    registry.register(AgentSpec("reporting", ("confidence",), ("reports",), _noop_handler))
    return registry


def test_clarification_answered_reruns_only_downstream_of_system_model():
    graph = InvalidationGraph(build_pipeline_registry())

    # Answering a clarification changes the system_model artifact itself
    # (produced by model_building). Only its consumers need to re-run —
    # model_building does not re-run itself just because its own output changed.
    affected = graph.compute_affected({"system_model"})

    assert affected == {"enumeration", "risk_mitigation", "assurance", "reporting"}


def test_review_item_accepted_reruns_only_downstream_of_risk_register():
    graph = InvalidationGraph(build_pipeline_registry())

    # Accepting a review item mutates the risk register/mitigations
    # artifacts directly (produced by risk_mitigation). Only their
    # consumers re-run — not risk_mitigation itself, and not the upstream
    # system model or enumeration output.
    affected = graph.compute_affected({"risk_register", "mitigations"})

    assert affected == {"assurance", "reporting"}


def test_intel_revision_reruns_only_downstream_of_adjudicated_threats():
    graph = InvalidationGraph(build_pipeline_registry())

    # Attaching intel produces a new adjudicated_threats artifact (via the
    # Intel Agent re-opening adjudications and admitting grounded candidates).
    # Only the agents that consume that artifact type need to re-run — not
    # model-building, and not the intel agent itself.
    affected = graph.compute_affected({"adjudicated_threats"})

    assert affected == {"risk_mitigation", "assurance", "reporting"}


def test_unrelated_artifact_change_affects_nothing():
    graph = InvalidationGraph(build_pipeline_registry())

    affected = graph.compute_affected({"unused_artifact_type"})

    assert affected == set()
