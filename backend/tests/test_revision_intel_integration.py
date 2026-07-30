from app.services.enumeration.bridge import build_technique_index
from app.services.enumeration.engine import CandidateThreat
from app.services.intel.models import AffectedProduct, ExtractedIntel
from app.services.intel.relevance import RelevanceResult
from app.services.kb.models import TechniqueChunk
from app.services.revision.intel_integration import (
    IntelInput,
    build_intel_candidates,
    corroborated_uplift,
    intel_bridged_techniques,
    intel_widened_entities,
)

CHUNKS = [
    TechniqueChunk(
        id="T1190", matrix="enterprise", name="Exploit Public-Facing Application",
        tactics=("initial-access",), description="exploit a public facing application",
        detection="", platforms=(), data_sources=(), relationships={"capec": ("CAPEC-1",)},
    ),
]
INDEX = build_technique_index(CHUNKS)


def _article(technique_ids, matched_entity_ids=(), content_hash="h1", fetched_at="2026-01-01T00:00:00Z"):
    return IntelInput(
        content_hash=content_hash,
        fetched_at=fetched_at,
        extracted=ExtractedIntel(technique_ids=tuple(technique_ids), affected_products=(AffectedProduct(vendor="v", product="p"),)),
        relevance=RelevanceResult(score=0.7, reasons=("matched",), matched_entity_ids=tuple(matched_entity_ids)),
    )


def test_corroborated_uplift_only_includes_kb_known_techniques():
    uplift = corroborated_uplift([_article(["T1190", "T9999"])], INDEX)
    assert uplift == {"T1190": 3.0}


def test_corroborated_uplift_takes_the_max_across_multiple_articles():
    uplift = corroborated_uplift(
        [_article(["T1190"]), _article(["T1190"])], INDEX, uplift_factor=5.0
    )
    assert uplift == {"T1190": 5.0}


def test_corroborated_uplift_empty_when_no_articles():
    assert corroborated_uplift([], INDEX) == {}


def test_intel_widened_entities_only_from_matching_technique():
    articles = [_article(["T1190"], matched_entity_ids=["gw"])]
    assert intel_widened_entities(articles, "T1190") == {"gw"}
    assert intel_widened_entities(articles, "T9999") == set()


def test_intel_widened_entities_unions_across_articles():
    articles = [
        _article(["T1190"], matched_entity_ids=["gw"], content_hash="h1"),
        _article(["T1190"], matched_entity_ids=["db"], content_hash="h2"),
    ]
    assert intel_widened_entities(articles, "T1190") == {"gw", "db"}


def test_build_intel_candidates_creates_one_per_entity_technique_pair():
    articles = [_article(["T1190"], matched_entity_ids=["gw"])]
    candidates = build_intel_candidates(articles, existing_candidate_keys=set())
    assert len(candidates) == 1
    candidate = candidates[0]
    assert candidate.element_id == "gw"
    assert candidate.framework == "intel"
    assert isinstance(candidate, CandidateThreat)


def test_build_intel_candidates_skips_pairs_already_covered_by_existing_candidates():
    articles = [_article(["T1190"], matched_entity_ids=["gw"])]
    candidates = build_intel_candidates(articles, existing_candidate_keys={("gw", "T1190")})
    assert candidates == []


def test_build_intel_candidates_deduplicates_across_multiple_articles():
    articles = [
        _article(["T1190"], matched_entity_ids=["gw"], content_hash="h1"),
        _article(["T1190"], matched_entity_ids=["gw"], content_hash="h2"),
    ]
    candidates = build_intel_candidates(articles, existing_candidate_keys=set())
    assert len(candidates) == 1


def test_intel_bridged_techniques_returns_real_citation_for_known_technique():
    bridged = intel_bridged_techniques("T1190", INDEX)
    assert len(bridged) == 1
    assert bridged[0].technique_id == "T1190"
    assert bridged[0].capec_ids == ("CAPEC-1",)


def test_intel_bridged_techniques_returns_empty_for_unknown_technique():
    assert intel_bridged_techniques("T9999", INDEX) == []
