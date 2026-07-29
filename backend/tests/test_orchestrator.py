import pytest

from app.orchestrator.budget import BudgetExceededError
from app.orchestrator.cache import compute_cache_key
from app.orchestrator.contracts import AgentContext, AgentSpec
from app.orchestrator.orchestrator import Orchestrator, ValidationError
from app.orchestrator.registry import AgentNotRegisteredError, AgentRegistry


def make_registry_with_stub(handler, name="stub", max_tool_calls=50):
    registry = AgentRegistry()
    registry.register(
        AgentSpec(
            name=name,
            input_artifact_types=("design_doc",),
            output_artifact_types=("system_model",),
            handler=handler,
            max_tool_calls=max_tool_calls,
        )
    )
    return registry


def test_registering_agent_makes_it_invocable():
    def handler(ctx: AgentContext) -> dict:
        return {"system_model": {"entities": []}}

    registry = make_registry_with_stub(handler)
    orchestrator = Orchestrator(registry)

    result = orchestrator.invoke("stub", {"design_doc": "graph TD; A-->B"})

    assert result.status == "complete"
    assert result.output_artifacts == {"system_model": {"entities": []}}
    assert result.cache_hit is False


def test_invoking_unregistered_agent_raises():
    registry = AgentRegistry()
    orchestrator = Orchestrator(registry)
    with pytest.raises(AgentNotRegisteredError):
        orchestrator.invoke("does-not-exist", {})


def test_cache_hit_is_byte_identical_with_zero_tool_calls():
    call_count = {"n": 0}

    def handler(ctx: AgentContext) -> dict:
        call_count["n"] += 1
        value = ctx.call_tool("parse", lambda x: x.upper(), ctx.input_artifacts["design_doc"])
        return {"system_model": value}

    registry = make_registry_with_stub(handler)
    orchestrator = Orchestrator(registry)
    inputs = {"design_doc": "graph td"}

    first = orchestrator.invoke("stub", inputs)
    second = orchestrator.invoke("stub", inputs)

    assert call_count["n"] == 1, "handler must not run again on a cache hit"
    assert second.cache_hit is True
    assert first.cache_hit is False
    assert second.output_artifacts == first.output_artifacts
    assert second.trajectory.tool_calls == first.trajectory.tool_calls


def test_cache_miss_still_enforces_validation_gate():
    def handler(ctx: AgentContext) -> dict:
        return {"system_model": {}}  # missing required "entities" key

    def validate(agent_name: str, output: dict) -> None:
        if "entities" not in output.get("system_model", {}):
            raise ValidationError(f"{agent_name}: system_model missing 'entities'")

    registry = make_registry_with_stub(handler)
    orchestrator = Orchestrator(registry, validate=validate)

    inputs = {"design_doc": "x"}
    with pytest.raises(ValidationError):
        orchestrator.invoke("stub", inputs)

    # an invalid trajectory must never be cached
    key = compute_cache_key("stub", inputs, {}, {})
    assert orchestrator.cache.get(key) is None


def test_budget_exceeded_raises_structured_error():
    def handler(ctx: AgentContext) -> dict:
        for _ in range(5):
            ctx.call_tool("noop", lambda: None)
        return {"system_model": {}}

    registry = make_registry_with_stub(handler, max_tool_calls=2)
    orchestrator = Orchestrator(registry)

    with pytest.raises(BudgetExceededError) as excinfo:
        orchestrator.invoke("stub", {"design_doc": "x"})

    assert excinfo.value.agent_name == "stub"
    assert excinfo.value.limit == 2
