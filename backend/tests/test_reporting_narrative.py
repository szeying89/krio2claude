import json

from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.reporting.narrative import (
    check_narrative_fact_provenance,
    extract_id_like_tokens,
    generate_audience_narrative,
)

PARAMS = CompletionParams(model="fake-model")


def test_extract_id_like_tokens_finds_technique_ids():
    assert extract_id_like_tokens("Exploiting T1190 via a public endpoint") == {"T1190"}


def test_extract_id_like_tokens_finds_atlas_ids_without_double_counting_technique_regex():
    tokens = extract_id_like_tokens("Model serving abused via AML.T0015")
    assert tokens == {"AML.T0015"}


def test_extract_id_like_tokens_finds_cve_ids():
    assert extract_id_like_tokens("affected by CVE-2024-1234") == {"CVE-2024-1234"}


def test_extract_id_like_tokens_finds_cri_statement_ids():
    assert extract_id_like_tokens("gap in PR.AA-05.01 coverage") == {"PR.AA-05.01"}


def test_extract_id_like_tokens_finds_d3fend_ids():
    assert extract_id_like_tokens("covered by D3-MFA") == {"D3-MFA"}


def test_extract_id_like_tokens_finds_path_ids():
    assert extract_id_like_tokens("see path-0123456789abcdef for detail") == {
        "path-0123456789abcdef"
    }


def test_extract_id_like_tokens_finds_candidate_threat_ids():
    assert extract_id_like_tokens("candidate gw::spoofing::1.0.0 was rejected") == {
        "gw::spoofing::1.0.0"
    }


def test_extract_id_like_tokens_ignores_ordinary_prose():
    assert extract_id_like_tokens("The gateway forwards requests to the processor.") == set()


def test_fact_provenance_passes_when_all_ids_are_known():
    result = check_narrative_fact_provenance("Risk is driven by T1190.", known_ids={"T1190"})
    assert result.satisfied is True


def test_fact_provenance_rejects_a_fabricated_id():
    result = check_narrative_fact_provenance("Risk is driven by T9999.", known_ids={"T1190"})
    assert result.satisfied is False
    assert "T9999" in result.detail


def test_fact_provenance_rejects_only_the_fabricated_subset():
    result = check_narrative_fact_provenance(
        "T1190 and T9999 both matter.", known_ids={"T1190"}
    )
    assert result.satisfied is False
    assert "T9999" in result.detail
    assert "T1190" not in result.detail


def test_generate_audience_narrative_returns_llm_text(tmp_path):
    response = json.dumps({"summary": "This model shows moderate confidence overall."})
    gateway = LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "cache")
    summary = generate_audience_narrative(gateway, PARAMS, "executive", "Overall confidence: 72/100")
    assert summary == "This model shows moderate confidence overall."


def test_generate_audience_narrative_defaults_to_empty_string(tmp_path):
    response = json.dumps({})
    gateway = LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "cache")
    summary = generate_audience_narrative(gateway, PARAMS, "ciso", "facts")
    assert summary == ""
