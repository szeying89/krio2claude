import json

from app.services.assurance.critique import (
    REASON_INVALID_SEVERITY,
    REASON_NO_CITATION,
    REASON_UNCITED_ELEMENT,
    REASON_UNCITED_STATEMENT,
    ReviewItem,
    check_review_item_grounding,
    generate_review_item,
)
from app.services.assurance.critique_detectors import CandidateIssue
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.systemmodel.models import Component, DeclaredControl, SystemModel

PARAMS = CompletionParams(model="fake-model")


def _model():
    return SystemModel(
        id="p1", version=1, parent_version=None,
        components=[Component(id="gw", name="Gateway", kind="process", trust_zone_id="tz")],
        declared_controls=[DeclaredControl(id="ctrl-1", name="Encryption", applies_to_ids=("gw",))],
    )


def _item(cited_element_ids=("gw",), cited_statement_ids=(), severity="high"):
    return ReviewItem(
        id="review-1", category="missed_threat", severity=severity, rationale="r",
        cited_element_ids=cited_element_ids, cited_statement_ids=cited_statement_ids,
    )


def test_valid_item_satisfies_grounding():
    result = check_review_item_grounding(_item(), _model(), known_statement_ids=set())
    assert result.satisfied is True


def test_item_with_no_citations_at_all_is_rejected():
    result = check_review_item_grounding(
        _item(cited_element_ids=(), cited_statement_ids=()), _model(), known_statement_ids=set()
    )
    assert result.satisfied is False
    assert result.reason_code == REASON_NO_CITATION


def test_item_citing_a_fabricated_element_is_rejected():
    result = check_review_item_grounding(
        _item(cited_element_ids=("not-real",)), _model(), known_statement_ids=set()
    )
    assert result.satisfied is False
    assert result.reason_code == REASON_UNCITED_ELEMENT


def test_item_citing_a_fabricated_statement_is_rejected():
    result = check_review_item_grounding(
        _item(cited_element_ids=(), cited_statement_ids=("NOT.REAL",)), _model(), known_statement_ids={"PR.AA-01.01"}
    )
    assert result.satisfied is False
    assert result.reason_code == REASON_UNCITED_STATEMENT


def test_item_citing_a_real_statement_id_is_accepted():
    result = check_review_item_grounding(
        _item(cited_element_ids=(), cited_statement_ids=("PR.AA-01.01",)), _model(), known_statement_ids={"PR.AA-01.01"}
    )
    assert result.satisfied is True


def test_item_citing_a_real_control_id_is_accepted():
    result = check_review_item_grounding(
        _item(cited_element_ids=("ctrl-1",)), _model(), known_statement_ids=set()
    )
    assert result.satisfied is True


def test_invalid_severity_is_rejected():
    result = check_review_item_grounding(
        _item(severity="catastrophic"), _model(), known_statement_ids=set()
    )
    assert result.satisfied is False
    assert result.reason_code == REASON_INVALID_SEVERITY


def test_generate_review_item_assigns_id_and_citations_deterministically(tmp_path):
    response = json.dumps({"severity": "high", "rationale": "this really matters"})
    gateway = LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "cache")
    candidate = CandidateIssue(category="missed_threat", cited_element_ids=("gw",), context="ctx")

    item = generate_review_item(gateway, PARAMS, candidate, item_id="review-abc")
    assert item.id == "review-abc"
    assert item.category == "missed_threat"
    assert item.cited_element_ids == ("gw",)
    assert item.severity == "high"
    assert item.rationale == "this really matters"


def test_generate_review_item_uses_default_severity_when_llm_omits_it(tmp_path):
    response = json.dumps({"rationale": "no severity given"})
    gateway = LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "cache")
    candidate = CandidateIssue(category="questionable_assumption", cited_element_ids=("gw",), context="ctx")

    item = generate_review_item(gateway, PARAMS, candidate, item_id="review-def")
    assert item.severity == "medium"
