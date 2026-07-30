import json

from app.services.kb.d3fend import D3fendTechnique
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.mitigation.recommendation import (
    REASON_UNCITED_CRI_STATEMENT,
    REASON_UNCITED_D3FEND,
    REASON_UNCITED_ENTITY,
    MitigationRecommendation,
    check_recommendation_grounding,
    generate_recommendation,
)

PARAMS = CompletionParams(model="fake-model")


def _gap(d3fend_gap_ids=("D3-MFA",), cri_gap_statement_ids=("PR.AA-05.01",)):
    return TechniqueGapAnalysis(
        technique_id="T1190",
        d3fend_required_ids=d3fend_gap_ids,
        d3fend_observed_ids=(),
        d3fend_gap_ids=d3fend_gap_ids,
        cri_mapping_absent=False,
        cri_in_tier_statement_ids=cri_gap_statement_ids,
        cri_gap_statement_ids=cri_gap_statement_ids,
        cri_mapping_inferred_fallback_ids=(),
    )


def _rec(d3fend_id="D3-MFA", cri_statement_ids=("PR.AA-05.01",), referenced_entity_ids=("gw",)):
    return MitigationRecommendation(
        id="rec-1",
        technique_id="T1190",
        d3fend_id=d3fend_id,
        cri_statement_ids=cri_statement_ids,
        guidance="Enable MFA on the Gateway.",
        referenced_entity_ids=referenced_entity_ids,
        effort=2,
    )


def test_valid_recommendation_satisfies_grounding():
    result = check_recommendation_grounding(_rec(), _gap(), candidate_entity_ids=("gw",))
    assert result.satisfied is True


def test_uncited_d3fend_id_is_rejected():
    result = check_recommendation_grounding(
        _rec(d3fend_id="D3-OTHER"), _gap(), candidate_entity_ids=("gw",)
    )
    assert result.satisfied is False
    assert result.reason_code == REASON_UNCITED_D3FEND


def test_fabricated_cri_statement_is_rejected():
    result = check_recommendation_grounding(
        _rec(cri_statement_ids=("PR.AA-05.01", "FABRICATED.01")), _gap(), candidate_entity_ids=("gw",)
    )
    assert result.satisfied is False
    assert result.reason_code == REASON_UNCITED_CRI_STATEMENT


def test_fabricated_entity_reference_is_rejected():
    result = check_recommendation_grounding(
        _rec(referenced_entity_ids=("gw", "not-a-real-entity")), _gap(), candidate_entity_ids=("gw",)
    )
    assert result.satisfied is False
    assert result.reason_code == REASON_UNCITED_ENTITY


def test_empty_cri_and_entity_references_are_always_valid():
    rec = _rec(cri_statement_ids=(), referenced_entity_ids=())
    result = check_recommendation_grounding(rec, _gap(), candidate_entity_ids=("gw",))
    assert result.satisfied is True


def test_generate_recommendation_resolves_entity_names_to_ids_and_fixes_d3fend_id(tmp_path):
    d3fend = D3fendTechnique(
        id="D3-MFA", tactic="Harden", name="Multi-factor Authentication", depth=0, parent_id=None,
        definition="Requiring multiple authentication factors.",
    )
    response = json.dumps(
        {
            "guidance": "Enable MFA on the Gateway.",
            "referenced_entity_names": ["Gateway"],
            "satisfied_cri_statement_ids": ["PR.AA-05.01"],
            "effort": 2,
        }
    )
    gateway = LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "llm-cache")

    rec = generate_recommendation(
        gateway,
        PARAMS,
        _gap(),
        technique_name="Privileged Access Control Bypass",
        technique_description="bypasses privileged access control",
        d3fend=d3fend,
        candidate_statement_texts={"PR.AA-05.01": "Sample diagnostic statement."},
        entity_names_by_id={"gw": "Gateway"},
        candidate_entity_ids=("gw",),
        recommendation_id="rec-T1190-D3-MFA",
    )

    assert rec.id == "rec-T1190-D3-MFA"
    assert rec.technique_id == "T1190"
    assert rec.d3fend_id == "D3-MFA"  # fixed deterministically, never LLM-chosen
    assert rec.cri_statement_ids == ("PR.AA-05.01",)
    assert rec.referenced_entity_ids == ("gw",)
    assert rec.effort == 2


def test_generate_recommendation_drops_entity_names_not_in_candidate_list(tmp_path):
    d3fend = D3fendTechnique(
        id="D3-MFA", tactic="Harden", name="Multi-factor Authentication", depth=0, parent_id=None,
        definition="Requiring multiple authentication factors.",
    )
    response = json.dumps(
        {
            "guidance": "Enable MFA everywhere, including the Historian.",
            "referenced_entity_names": ["Gateway", "Historian"],  # Historian isn't a candidate
            "satisfied_cri_statement_ids": [],
            "effort": 1,
        }
    )
    gateway = LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "llm-cache")

    rec = generate_recommendation(
        gateway,
        PARAMS,
        _gap(),
        technique_name="Privileged Access Control Bypass",
        technique_description="bypasses privileged access control",
        d3fend=d3fend,
        candidate_statement_texts={},
        entity_names_by_id={"gw": "Gateway", "hist": "Historian"},
        candidate_entity_ids=("gw",),  # only Gateway is a real candidate for this technique
        recommendation_id="rec-T1190-D3-MFA",
    )
    assert rec.referenced_entity_ids == ("gw",)
