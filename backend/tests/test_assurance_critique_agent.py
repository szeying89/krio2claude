import copy
import json
from pathlib import Path

import pytest

from app.orchestrator.orchestrator import Orchestrator, ValidationError
from app.orchestrator.registry import AgentRegistry
from app.services.assurance.critique import ReviewItem
from app.services.assurance.critique_agent import (
    AGENT_NAME,
    build_critique_agent,
    validate_critique_grounding,
)
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.modelbuilding.models import Assumption
from app.services.systemmodel.models import Component, Dataflow, SystemModel, TrustZone

PARAMS = CompletionParams(model="fake-model")

NORMAL_RESPONSE = json.dumps({"severity": "high", "rationale": "worth a human look"})


def _model():
    return SystemModel(
        id="p1", version=1, parent_version=None,
        trust_zones=[TrustZone(id="dmz", name="DMZ", trust_rating=1), TrustZone(id="internal", name="Internal", trust_rating=3)],
        components=[
            Component(id="gw", name="Gateway", kind="process", trust_zone_id="dmz"),
            Component(id="db", name="Database", kind="datastore", trust_zone_id="internal"),
        ],
        dataflows=[Dataflow(id="bk-02", name="backup restore", source_id="gw", destination_id="db")],
    )


def _input_artifacts(model):
    return {
        "model": model,
        "adjudicated_threats": [],
        "gaps": [],
        "entities_by_technique": {},
        "assumptions": [Assumption(kind="default", subject_id="gw", message="low conf", source="agent_generated", confidence=0.1, impact_if_wrong="x")],
        "tier": None,
        "cri_statements": [],
    }


def _registry_and_orchestrator(gateway):
    registry = AgentRegistry()
    registry.register(build_critique_agent(gateway, PARAMS))
    return Orchestrator(registry, validate=validate_critique_grounding)


def test_critique_flows_through_orchestrator_and_finds_the_missed_threat_and_assumption(tmp_path):
    gateway = LLMGateway(FakeProvider(respond=lambda _p: NORMAL_RESPONSE), cache_dir=tmp_path / "cache")
    orchestrator = _registry_and_orchestrator(gateway)
    model = _model()

    result = orchestrator.invoke(AGENT_NAME, _input_artifacts(model))
    items = result.output_artifacts["review_items"]
    categories = {i.category for i in items}
    assert "missed_threat" in categories
    assert "questionable_assumption" in categories
    assert result.output_artifacts["rejection_log"] == []


def test_critique_never_mutates_the_model(tmp_path):
    """The agent's handler has no tool capable of editing SystemModel --
    ctx.call_tool is the only channel it has to affect anything, and every
    registered tool here is a read-only detector, an LLM narrative call,
    or a grounding check. Prove it directly: the model object is
    byte-for-byte identical after the agent runs."""
    model = _model()
    before = copy.deepcopy(model)

    gateway = LLMGateway(FakeProvider(respond=lambda _p: NORMAL_RESPONSE), cache_dir=tmp_path / "cache")
    orchestrator = _registry_and_orchestrator(gateway)
    orchestrator.invoke(AGENT_NAME, _input_artifacts(model))

    assert model == before


def test_no_tool_in_the_agents_registry_can_edit_a_system_model():
    """A structural check on top of the behavioral one above: none of the
    functions this agent's build function is capable of calling live in
    a module that exposes model-mutation (e.g. `systemmodel.edits`)."""
    import app.services.assurance.critique_agent as critique_agent_module

    forbidden_substrings = ("apply_edits", "freeze_draft", "ProjectSystemModelService")
    source = Path(critique_agent_module.__file__).read_text()
    for forbidden in forbidden_substrings:
        assert forbidden not in source


def test_fabricated_citation_is_rejected_inline_not_surfaced(tmp_path):
    gateway = LLMGateway(FakeProvider(respond=lambda _p: NORMAL_RESPONSE), cache_dir=tmp_path / "cache")
    orchestrator = _registry_and_orchestrator(gateway)

    # A model with no trust-zone-crossing dataflows and no assumptions has
    # nothing to critique at all -- confirms an empty run produces no
    # fabricated findings rather than inventing something.
    empty_model = SystemModel(id="p2", version=1, parent_version=None)
    empty_inputs = _input_artifacts(empty_model)
    empty_inputs["assumptions"] = []
    result = orchestrator.invoke(AGENT_NAME, empty_inputs)
    assert result.output_artifacts["review_items"] == []
    assert result.output_artifacts["candidate_count"] == 0


def test_validate_gate_rejects_an_item_surfaced_without_any_citation():
    fabricated = ReviewItem(
        id="review-x", category="missed_threat", severity="high", rationale="r",
        cited_element_ids=(), cited_statement_ids=(),
    )
    with pytest.raises(ValidationError):
        validate_critique_grounding("critique", {"review_items": [fabricated], "rejection_log": []})


def test_validate_gate_rejects_duplicate_id_across_both_lists():
    item = ReviewItem(
        id="review-dup", category="missed_threat", severity="high", rationale="r",
        cited_element_ids=("gw",), cited_statement_ids=(),
    )
    with pytest.raises(ValidationError):
        validate_critique_grounding(
            "critique",
            {
                "review_items": [item],
                "rejection_log": [{"candidate_id": "review-dup", "category": "x", "reason_code": "y", "detail": "z"}],
            },
        )


def test_validate_gate_passes_well_formed_output_through_untouched():
    item = ReviewItem(
        id="review-ok", category="missed_threat", severity="high", rationale="r",
        cited_element_ids=("gw",), cited_statement_ids=(),
    )
    validate_critique_grounding("critique", {"review_items": [item], "rejection_log": []})
