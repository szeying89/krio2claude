"""Task 23: integration-tests the seven real AgentSpecs this platform
actually ships (Model-Building, Enumeration, Risk & Mitigation, Assurance
[critique], Intel, Revision, Reporting) registered together in ONE shared
`AgentRegistry`/`Orchestrator`, using real (not stubbed) agent handlers —
not the synthetic `AgentSpec` stand-ins `test_invalidation_graph.py` and
`test_orchestrator.py` use to exercise Task 1b's abstract contract.

An honest finding worth stating up front: the plan's architecture diagram
draws a clean six-agent chain (model-building -> enumeration -> risk &
mitigation -> assurance -> reporting, with intel feeding back in), but
each task named its own artifact types independently as it was built
(`system_model_draft` vs. `system_model`, `gaps` as a tool-computed
intermediate no agent ever emits, `report_data` echoed back by reporting
itself). The real bridging between agents happens through deterministic
glue functions in the API layer (`compute_technique_gaps`,
`entities_by_technique`, ...) — exactly "tools, not agent judgment" per
the architecture doc — not through the invalidation graph auto-chaining
agent outputs into agent inputs. `test_invalidation_graph_over_real_agents`
below verifies what is actually true rather than asserting the idealized
diagram: `system_model` is the one real shared artifact type three of the
seven agents (enumeration, critique, revision) declare as a direct input,
and nothing else chains further.
"""

import json

from app.orchestrator.invalidation import InvalidationGraph
from app.orchestrator.orchestrator import Orchestrator
from app.orchestrator.registry import AgentRegistry
from app.services.assurance.critique_agent import (
    AGENT_NAME as CRITIQUE_AGENT_NAME,
)
from app.services.assurance.critique_agent import build_critique_agent, validate_critique_grounding
from app.services.assurance.rubric import ConfidenceReport, RubricDimension
from app.services.enumeration.agent import (
    AGENT_NAME as ENUMERATION_AGENT_NAME,
)
from app.services.enumeration.agent import build_enumeration_agent, validate_enumeration_grounding
from app.services.enumeration.ruleset import load_ruleset
from app.services.intel.agent import AGENT_NAME as INTEL_AGENT_NAME
from app.services.intel.agent import build_intel_agent
from app.services.kb.d3fend import D3fendTechnique
from app.services.kb.models import TechniqueChunk
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.mitigation.agent import AGENT_NAME as MITIGATION_AGENT_NAME
from app.services.mitigation.agent import build_mitigation_agent, validate_mitigation_grounding
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.modelbuilding.agent import (
    AGENT_NAME as MODEL_BUILDING_AGENT_NAME,
)
from app.services.modelbuilding.agent import build_model_building_agent
from app.services.reporting.agent import AGENT_NAME as REPORTING_AGENT_NAME
from app.services.reporting.agent import build_reporting_agent, validate_reporting_fact_provenance
from app.services.reporting.models import ReportData
from app.services.revision.agent import AGENT_NAME as REVISION_AGENT_NAME
from app.services.revision.agent import build_revision_agent
from app.services.risk.models import CSFFunctionRollup, RiskFactors, RiskFinding
from app.services.systemmodel.models import Component, Dataflow, SystemModel, TrustZone

PARAMS = CompletionParams(model="fake-model")


def _model() -> SystemModel:
    return SystemModel(
        id="p1",
        version=1,
        parent_version=None,
        trust_zones=[
            TrustZone(id="dmz", name="DMZ", trust_rating=1),
            TrustZone(id="internal", name="Internal", trust_rating=3),
        ],
        components=[
            Component(id="gw", name="Gateway", kind="process", trust_zone_id="dmz"),
            Component(id="db", name="Database", kind="datastore", trust_zone_id="internal"),
        ],
        dataflows=[Dataflow(id="bk-02", name="backup restore", source_id="gw", destination_id="db")],
    )


def build_full_agent_registry(gateway: LLMGateway) -> AgentRegistry:
    """Registers all seven real AgentSpecs this platform ships. Mirrors
    what every API endpoint already does per-agent (each creates its own
    single-agent registry) but combined into one, to prove real agent
    handlers coexist in a shared registry/orchestrator without name or
    cache-key collisions."""
    ruleset = load_ruleset()
    registry = AgentRegistry()
    registry.register(build_model_building_agent(gateway, PARAMS))
    registry.register(build_enumeration_agent(ruleset, index=None))
    registry.register(build_mitigation_agent(gateway, PARAMS))
    registry.register(build_critique_agent(gateway, PARAMS))
    registry.register(build_intel_agent(gateway, PARAMS))
    registry.register(build_revision_agent())
    registry.register(build_reporting_agent(gateway, PARAMS))
    return registry


def _combined_validate(agent_name: str, output_artifacts: dict) -> None:
    """The real per-agent validate gates dispatched by agent name — proves
    each agent's own fact-provenance/grounding rules apply only to its own
    output, never cross-checked against a different agent's shape."""
    if agent_name == ENUMERATION_AGENT_NAME:
        validate_enumeration_grounding(agent_name, output_artifacts)
    elif agent_name == MITIGATION_AGENT_NAME:
        validate_mitigation_grounding(agent_name, output_artifacts)
    elif agent_name == CRITIQUE_AGENT_NAME:
        validate_critique_grounding(agent_name, output_artifacts)
    elif agent_name == REPORTING_AGENT_NAME:
        validate_reporting_fact_provenance(agent_name, output_artifacts)
    # model_building, intel, and revision have no orchestrator-level
    # validate gate of their own (model_building's completeness/precedence
    # rules and intel's instruction-stripping live at the tool boundary;
    # revision's grounding check is registered separately by callers that
    # need it, mirroring app/api/revisions.py's own real usage).


def test_all_seven_real_agents_register_without_collision(tmp_path):
    gateway = LLMGateway(FakeProvider(respond=lambda _p: "{}"), cache_dir=tmp_path / "cache")
    registry = build_full_agent_registry(gateway)

    names = {spec.name for spec in registry.all_specs()}
    assert names == {
        MODEL_BUILDING_AGENT_NAME,
        ENUMERATION_AGENT_NAME,
        MITIGATION_AGENT_NAME,
        CRITIQUE_AGENT_NAME,
        INTEL_AGENT_NAME,
        REVISION_AGENT_NAME,
        REPORTING_AGENT_NAME,
    }
    assert len(names) == 7


def test_invalidation_graph_over_real_agents_finds_system_model_as_the_shared_bridge(tmp_path):
    gateway = LLMGateway(FakeProvider(respond=lambda _p: "{}"), cache_dir=tmp_path / "cache")
    registry = build_full_agent_registry(gateway)
    graph = InvalidationGraph(registry)

    # system_model is a direct declared input of three real agents.
    affected = graph.compute_affected({"system_model"})
    assert affected == {ENUMERATION_AGENT_NAME, CRITIQUE_AGENT_NAME, REVISION_AGENT_NAME}

    # Every other real artifact type is agent-local: it affects only the
    # single agent that declares it as input, and does not cascade,
    # because no other real agent's declared input matches any of that
    # agent's declared outputs (the deterministic glue code that actually
    # bridges agents in app/api/*.py lives outside the agent graph).
    assert graph.compute_affected({"design_document"}) == {MODEL_BUILDING_AGENT_NAME}
    assert graph.compute_affected({"gaps"}) == {MITIGATION_AGENT_NAME}
    assert graph.compute_affected({"article_text"}) == {INTEL_AGENT_NAME}
    assert graph.compute_affected({"report_data"}) == {REPORTING_AGENT_NAME}
    assert graph.compute_affected({"unused_artifact_type"}) == set()


NORMAL_CRITIQUE_RESPONSE = json.dumps({"severity": "high", "rationale": "worth a human look"})


def _confidence():
    dim = RubricDimension(name="x", score=72.0, weight=1 / 6, raw_counts={}, detail="")
    return ConfidenceReport(dimensions=(dim,) * 6, overall_score=72.0, band="Moderate")


def _report_data():
    finding = RiskFinding(
        path_id="path-1", entry_point="gw", target="db", technique_ids=("T1190",),
        tactic_sequence=("initial-access",), score=0.5,
        factors=RiskFactors(likelihood=0.5, impact_weight=0.75, statement_density=0.0, d3fend_gap_count=0, cri_gap_count=0, cri_mapping_absent=False),
        csf_functions=("PR",), regulatory_exposure=(),
    )
    return ReportData(
        project_name="Demo", business_criticality="high", model=_model(), confidence=_confidence(),
        risk_findings=(finding,), csf_rollup=(CSFFunctionRollup("PR", 1, 1, 0, 0.0),),
        tier=None, tier_justification="not computed", gaps=(), residual_risk=None, roadmap=(),
        recommendations=(), adjudicated_threats=(), rejection_log=(), assumptions=(), currency=None,
        has_cri=False,
    )


def _dispatching_respond(prompt: str) -> str:
    if "one mitigation recommendation" in prompt:
        return json.dumps({"guidance": "Deploy MFA.", "referenced_entity_names": [], "satisfied_cri_statement_ids": [], "effort": 2})
    if "narrative summary section" in prompt:
        return json.dumps({"summary": "This model shows T1190 as the leading risk driver."})
    return NORMAL_CRITIQUE_RESPONSE


def test_shared_orchestrator_runs_mixed_llm_and_zero_llm_agents_without_cross_contamination(tmp_path):
    """Enumeration (zero LLM calls, per the plan) and three LLM-backed
    agents (mitigation, critique, reporting) share one Orchestrator
    instance and one combined validate dispatcher. Each agent's own
    grounding rule must apply only to its own output."""
    gateway = LLMGateway(FakeProvider(respond=_dispatching_respond), cache_dir=tmp_path / "cache")
    registry = build_full_agent_registry(gateway)
    orchestrator = Orchestrator(registry, validate=_combined_validate)

    model = _model()

    enum_result = orchestrator.invoke(
        ENUMERATION_AGENT_NAME, {"model": model, "atlas_enabled": False}
    )
    assert enum_result.status == "complete"
    assert enum_result.cache_hit is False

    gap = TechniqueGapAnalysis(
        technique_id="T1190", d3fend_required_ids=("D3-MFA",), d3fend_observed_ids=(),
        d3fend_gap_ids=("D3-MFA",), cri_mapping_absent=False,
        cri_in_tier_statement_ids=("PR.AA-05.01",), cri_gap_statement_ids=("PR.AA-05.01",),
        cri_mapping_inferred_fallback_ids=(),
    )
    technique = TechniqueChunk(
        id="T1190", matrix="enterprise", name="Privileged Access Control Bypass",
        tactics=("initial-access",), description="bypasses privileged access control",
        detection="", platforms=(), data_sources=(), relationships={},
    )
    d3fend = D3fendTechnique(
        id="D3-MFA", tactic="Harden", name="Multi-factor Authentication", depth=0,
        parent_id=None, definition="Requiring multiple authentication factors.",
    )
    mitigation_result = orchestrator.invoke(
        MITIGATION_AGENT_NAME,
        {
            "gaps": [gap], "techniques_by_id": {"T1190": technique}, "d3fend_by_id": {"D3-MFA": d3fend},
            "cri_statement_texts": {"PR.AA-05.01": "Sample diagnostic statement."},
            "entity_names_by_id": {"gw": "Gateway"}, "entities_by_technique": {"T1190": ("gw",)},
        },
    )
    assert len(mitigation_result.output_artifacts["recommendations"]) == 1

    critique_result = orchestrator.invoke(
        CRITIQUE_AGENT_NAME,
        {
            "model": model, "adjudicated_threats": [], "gaps": [], "entities_by_technique": {},
            "assumptions": [], "tier": None, "cri_statements": [],
        },
    )
    categories = {item.category for item in critique_result.output_artifacts["review_items"]}
    assert "missed_threat" in categories

    reporting_result = orchestrator.invoke(REPORTING_AGENT_NAME, {"report_data": _report_data()})
    assert set(reporting_result.output_artifacts["narratives"]) == {"executive", "ciso", "technical"}

    # Re-invoking enumeration with identical inputs is a cache hit and did
    # not re-run mitigation's, critique's, or reporting's validate rules
    # against its own (very different-shaped) output — if it had, this
    # would raise, since enumeration's output has no "recommendations" /
    # "review_items" / "narratives" keys at all.
    repeat = orchestrator.invoke(ENUMERATION_AGENT_NAME, {"model": model, "atlas_enabled": False})
    assert repeat.cache_hit is True
    assert repeat.output_artifacts == enum_result.output_artifacts


def test_cache_miss_in_shared_registry_still_enforces_the_right_agents_gate(tmp_path):
    """A fabricated technique id from the LLM must still be caught by
    reporting's own gate even when invoked from a registry holding six
    other, unrelated agents."""

    def _respond(prompt: str) -> str:
        if "narrative summary section" in prompt:
            return json.dumps({"summary": "Driven by fabricated technique T9999."})
        return NORMAL_CRITIQUE_RESPONSE

    gateway = LLMGateway(FakeProvider(respond=_respond), cache_dir=tmp_path / "cache")
    registry = build_full_agent_registry(gateway)
    orchestrator = Orchestrator(registry, validate=_combined_validate)

    result = orchestrator.invoke(REPORTING_AGENT_NAME, {"report_data": _report_data()})
    # Reporting's own inline check rejects the fabrication into its
    # rejection_log rather than raising -- the orchestrator's independent
    # gate (validate_reporting_fact_provenance) only raises on a
    # hand-constructed bypass of that inline check, exercised directly in
    # test_reporting_agent.py. Here we confirm the shared-registry
    # invocation still produces the same, correctly-scoped rejection.
    assert result.output_artifacts["narratives"] == {}
    assert len(result.output_artifacts["rejection_log"]) == 3


def test_disk_backed_gateway_cache_is_a_hit_across_brand_new_gateway_instances(tmp_path):
    """The orchestrator's in-memory TrajectoryCache is thrown away every
    time a fresh Orchestrator is constructed (exactly what every real API
    endpoint does per-request, per app/api/reports.py etc.) -- so the
    property that actually survives across independent requests is the
    LLM gateway's own disk-backed ContentAddressedCache. This proves an
    entirely new LLMGateway/FakeProvider pair, pointed at the same
    cache_dir, produces zero additional provider calls for an identical
    prompt: a real "identical reruns are byte-identical, with no repeated
    LLM work" property, not merely an in-process one."""
    cache_dir = tmp_path / "shared-cache"

    provider_one = FakeProvider(respond=_dispatching_respond)
    gateway_one = LLMGateway(provider_one, cache_dir=cache_dir)
    registry_one = AgentRegistry()
    registry_one.register(build_reporting_agent(gateway_one, PARAMS))
    orchestrator_one = Orchestrator(registry_one, validate=_combined_validate)
    result_one = orchestrator_one.invoke(REPORTING_AGENT_NAME, {"report_data": _report_data()})
    assert len(provider_one.calls) == 3  # one narrative generation call per audience

    provider_two = FakeProvider(respond=_dispatching_respond)
    gateway_two = LLMGateway(provider_two, cache_dir=cache_dir)
    registry_two = AgentRegistry()
    registry_two.register(build_reporting_agent(gateway_two, PARAMS))
    orchestrator_two = Orchestrator(registry_two, validate=_combined_validate)
    result_two = orchestrator_two.invoke(REPORTING_AGENT_NAME, {"report_data": _report_data()})

    assert len(provider_two.calls) == 0, "a brand-new gateway sharing the disk cache must never call the provider again"
    assert result_two.output_artifacts["narratives"] == result_one.output_artifacts["narratives"]
