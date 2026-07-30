"""Mirrors Task 1b's demo: register a no-op stub agent, invoke it twice with
identical inputs (second call is a cache hit), then change one input and see
the invalidation graph mark exactly the correct downstream stub agents dirty.
"""

from app.orchestrator.contracts import AgentContext, AgentSpec
from app.orchestrator.orchestrator import Orchestrator
from app.orchestrator.registry import AgentRegistry


def test_stub_agent_cache_hit_then_invalidation_on_changed_input():
    calls = {"upstream": 0, "downstream": 0}

    def upstream_handler(ctx: AgentContext) -> dict:
        calls["upstream"] += 1
        return {"system_model": ctx.input_artifacts["design_doc"]}

    def downstream_handler(ctx: AgentContext) -> dict:
        calls["downstream"] += 1
        return {"risk_register": ctx.input_artifacts["system_model"]}

    registry = AgentRegistry()
    registry.register(
        AgentSpec("upstream", ("design_doc",), ("system_model",), upstream_handler)
    )
    registry.register(
        AgentSpec("downstream", ("system_model",), ("risk_register",), downstream_handler)
    )
    orchestrator = Orchestrator(registry)

    first = orchestrator.invoke("upstream", {"design_doc": "graph TD; A-->B"})
    assert calls["upstream"] == 1
    assert first.cache_hit is False

    second = orchestrator.invoke("upstream", {"design_doc": "graph TD; A-->B"})
    assert calls["upstream"] == 1, "identical input must be a cache hit, not a re-run"
    assert second.cache_hit is True
    assert second.output_artifacts == first.output_artifacts

    # Now change the input: the invalidation graph should mark exactly the
    # agents downstream of the changed artifact type as dirty. design_doc
    # changing affects upstream directly, and cascades to downstream because
    # upstream's output (system_model) is what downstream consumes.
    dirty = orchestrator.compute_affected({"design_doc"})
    assert dirty == {"upstream", "downstream"}

    # Changing system_model alone (without touching design_doc) invalidates
    # only downstream — upstream doesn't re-run just because its own output changed.
    dirty = orchestrator.compute_affected({"system_model"})
    assert dirty == {"downstream"}

    third = orchestrator.invoke("upstream", {"design_doc": "graph TD; A-->B-->C"})
    assert calls["upstream"] == 2, "a genuinely different input must not be a cache hit"
    assert third.cache_hit is False
    assert third.output_artifacts != first.output_artifacts
