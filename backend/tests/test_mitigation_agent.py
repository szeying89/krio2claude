import json

import pytest

from app.orchestrator.orchestrator import Orchestrator, ValidationError
from app.orchestrator.registry import AgentRegistry
from app.services.kb.d3fend import D3fendTechnique
from app.services.kb.models import TechniqueChunk
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.mitigation.agent import (
    AGENT_NAME,
    RecommendationRejection,
    build_mitigation_agent,
    validate_mitigation_grounding,
)
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.mitigation.recommendation import MitigationRecommendation

PARAMS = CompletionParams(model="fake-model")

GAP = TechniqueGapAnalysis(
    technique_id="T1190",
    d3fend_required_ids=("D3-MFA",),
    d3fend_observed_ids=(),
    d3fend_gap_ids=("D3-MFA",),
    cri_mapping_absent=False,
    cri_in_tier_statement_ids=("PR.AA-05.01",),
    cri_gap_statement_ids=("PR.AA-05.01",),
    cri_mapping_inferred_fallback_ids=(),
)

TECHNIQUE = TechniqueChunk(
    id="T1190", matrix="enterprise", name="Privileged Access Control Bypass",
    tactics=("initial-access",), description="bypasses privileged access control",
    detection="", platforms=(), data_sources=(), relationships={},
)

D3FEND = D3fendTechnique(
    id="D3-MFA", tactic="Harden", name="Multi-factor Authentication", depth=0, parent_id=None,
    definition="Requiring multiple authentication factors.",
)


def _input_artifacts():
    return {
        "gaps": [GAP],
        "techniques_by_id": {"T1190": TECHNIQUE},
        "d3fend_by_id": {"D3-MFA": D3FEND},
        "cri_statement_texts": {"PR.AA-05.01": "Sample diagnostic statement."},
        "entity_names_by_id": {"gw": "Gateway"},
        "entities_by_technique": {"T1190": ("gw",)},
    }


def _registry_and_orchestrator(gateway, validate=validate_mitigation_grounding):
    registry = AgentRegistry()
    registry.register(build_mitigation_agent(gateway, PARAMS))
    return Orchestrator(registry, validate=validate)


@pytest.mark.asyncio
async def test_grounded_recommendation_flows_through_orchestrator(tmp_path):
    response = json.dumps(
        {
            "guidance": "Enable MFA on the Gateway.",
            "referenced_entity_names": ["Gateway"],
            "satisfied_cri_statement_ids": ["PR.AA-05.01"],
            "effort": 2,
        }
    )
    gateway = LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "cache")
    orchestrator = _registry_and_orchestrator(gateway)

    result = orchestrator.invoke(AGENT_NAME, _input_artifacts())
    assert result.status == "complete"
    assert len(result.output_artifacts["recommendations"]) == 1
    assert result.output_artifacts["rejection_log"] == []
    assert result.output_artifacts["gap_count"] == 1

    rec = result.output_artifacts["recommendations"][0]
    assert rec.d3fend_id == "D3-MFA"
    assert rec.cri_statement_ids == ("PR.AA-05.01",)


@pytest.mark.asyncio
async def test_fabricated_cri_citation_is_rejected_inline_not_surfaced(tmp_path):
    response = json.dumps(
        {
            "guidance": "Enable MFA on the Gateway.",
            "referenced_entity_names": ["Gateway"],
            "satisfied_cri_statement_ids": ["FABRICATED.01"],  # not a real gap for this technique
            "effort": 2,
        }
    )
    gateway = LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "cache")
    orchestrator = _registry_and_orchestrator(gateway)

    result = orchestrator.invoke(AGENT_NAME, _input_artifacts())
    assert result.output_artifacts["recommendations"] == []
    assert len(result.output_artifacts["rejection_log"]) == 1
    assert result.output_artifacts["rejection_log"][0].reason_code == "uncited_cri_statement"


def test_validate_gate_rejects_a_recommendation_surfaced_without_a_d3fend_citation():
    fabricated = MitigationRecommendation(
        id="rec-x", technique_id="T1190", d3fend_id="", cri_statement_ids=(),
        guidance="text", referenced_entity_ids=(), effort=1,
    )
    with pytest.raises(ValidationError):
        validate_mitigation_grounding(
            "mitigation", {"recommendations": [fabricated], "rejection_log": []}
        )


def test_validate_gate_rejects_a_recommendation_id_appearing_in_both_lists():
    rec = MitigationRecommendation(
        id="rec-dup", technique_id="T1190", d3fend_id="D3-MFA", cri_statement_ids=(),
        guidance="text", referenced_entity_ids=(), effort=1,
    )
    rejection = RecommendationRejection(
        recommendation_id="rec-dup", technique_id="T1190", reason_code="uncited_entity", detail="x"
    )
    with pytest.raises(ValidationError):
        validate_mitigation_grounding(
            "mitigation", {"recommendations": [rec], "rejection_log": [rejection]}
        )


def test_validate_gate_passes_well_formed_output_through_untouched():
    rec = MitigationRecommendation(
        id="rec-ok", technique_id="T1190", d3fend_id="D3-MFA", cri_statement_ids=("PR.AA-05.01",),
        guidance="text", referenced_entity_ids=(), effort=1,
    )
    validate_mitigation_grounding("mitigation", {"recommendations": [rec], "rejection_log": []})
