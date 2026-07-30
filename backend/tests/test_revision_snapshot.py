from app.models.enums import BusinessCriticality
from app.services.enumeration.bridge import build_technique_index
from app.services.enumeration.ruleset import load_ruleset
from app.services.intel.models import AffectedProduct, ExtractedIntel
from app.services.intel.relevance import RelevanceResult
from app.services.kb.models import TechniqueChunk
from app.services.revision.intel_integration import IntelInput
from app.services.revision.snapshot import compute_snapshot
from app.services.systemmodel.models import Asset, Component, Dataflow, SystemModel, TrustZone

RULESET = load_ruleset()

CHUNKS = [
    TechniqueChunk(
        id="T1499",
        matrix="enterprise",
        name="Endpoint Denial of Service",
        tactics=("impact",),
        description="Adversaries may flood a target host to exhaust resources and deny service, "
        "tampering with availability via denial of service.",
        detection="",
        platforms=(),
        data_sources=(),
        relationships={"capec": ("CAPEC-125",)},
    ),
]
INDEX = build_technique_index(CHUNKS)
TECHNIQUES_BY_ID = {c.id: c for c in CHUNKS}


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
            Component(id="client", name="Client", kind="external_entity", trust_zone_id="dmz"),
            Component(id="gw", name="Gateway", kind="process", trust_zone_id="dmz"),
            Component(id="isolated", name="Isolated Batch Job", kind="process", trust_zone_id="internal"),
        ],
        dataflows=[Dataflow(id="f1", name="login", source_id="client", destination_id="gw")],
        assets=[
            Asset(
                id="a1", name="Session Store", classification="confidential",
                confidentiality=8, integrity=5, availability=5, owner_id="gw",
            )
        ],
    )


def _snapshot(articles=()):
    return compute_snapshot(
        model=_model(),
        ruleset=RULESET,
        index=INDEX,
        techniques_by_id=TECHNIQUES_BY_ID,
        d3fend_catalog=[],
        cri_statements=[],
        regulatory_documents={},
        tier=None,
        business_criticality=BusinessCriticality.HIGH,
        atlas_enabled=False,
        articles=list(articles),
        kb_fetched_at="2026-01-01T00:00:00Z",
        cri_fetched_at=None,
    )


def _article(technique_ids, matched_entity_ids=()):
    return IntelInput(
        content_hash="h1",
        fetched_at="2026-02-01T00:00:00Z",
        extracted=ExtractedIntel(
            technique_ids=tuple(technique_ids),
            affected_products=(AffectedProduct(vendor="v", product="p"),),
        ),
        relevance=RelevanceResult(score=0.7, reasons=("matched",), matched_entity_ids=tuple(matched_entity_ids)),
    )


def test_baseline_has_an_unreachable_isolated_component_and_a_reachable_gateway():
    snapshot = _snapshot()
    verdicts = {a.candidate_threat_id: a.verdict for a in snapshot.adjudications}
    isolated_ids = [cid for cid in verdicts if "isolated" in cid]
    gw_ids = [cid for cid in verdicts if cid.startswith("gw::") or "::gw::" in cid]
    assert isolated_ids
    assert all(verdicts[cid] == "not_applicable" for cid in isolated_ids)
    assert gw_ids
    assert any(verdicts[cid] == "applicable" for cid in gw_ids)


def test_irrelevant_intel_produces_a_zero_change_diff():
    from app.services.revision.diff import compute_diff

    baseline = _snapshot()
    irrelevant = _snapshot(articles=[_article(["T9999"], matched_entity_ids=[])])
    diff = compute_diff(baseline, irrelevant)

    assert diff.new_path_ids == ()
    assert diff.removed_path_ids == ()
    assert diff.changed_paths == ()
    assert diff.reopened_adjudication_ids == ()
    assert diff.risk_score_delta == 0.0


def test_corroborating_intel_raises_path_likelihoods():
    baseline = _snapshot()
    corroborated = _snapshot(articles=[_article(["T1499"])])

    assert baseline.paths, "fixture must produce at least one baseline path"
    baseline_by_id = {p.id: p.aggregate_likelihood for p in baseline.paths}
    corroborated_by_id = {p.id: p.aggregate_likelihood for p in corroborated.paths}

    assert set(baseline_by_id) == set(corroborated_by_id)
    for path_id, baseline_likelihood in baseline_by_id.items():
        assert corroborated_by_id[path_id] > baseline_likelihood


def test_contradicting_intel_reopens_exactly_the_matching_adjudication():
    baseline = _snapshot()
    baseline_verdicts = {a.candidate_threat_id: a.verdict for a in baseline.adjudications}
    isolated_ids = {cid for cid, verdict in baseline_verdicts.items() if verdict == "not_applicable"}
    assert isolated_ids

    contradicted = _snapshot(articles=[_article(["T1499"], matched_entity_ids=["isolated"])])
    contradicted_verdicts = {a.candidate_threat_id: a.verdict for a in contradicted.adjudications}

    reopened = {cid for cid in isolated_ids if contradicted_verdicts.get(cid) == "applicable"}
    assert reopened == isolated_ids  # every previously not_applicable stride candidate reopens

    # nothing that was already applicable flips to not_applicable as a side effect
    for cid, verdict in baseline_verdicts.items():
        if verdict == "applicable":
            assert contradicted_verdicts[cid] == "applicable"


def test_intel_only_claim_without_real_grounding_never_becomes_a_finding():
    snapshot = _snapshot(articles=[_article(["T0000-NOT-REAL"], matched_entity_ids=["gw"])])
    assert not any(
        a.candidate_threat_id == "intel::gw::T0000-NOT-REAL" for a in snapshot.adjudications
    )


def test_baseline_confidence_is_between_zero_and_one():
    snapshot = _snapshot()
    assert 0.0 <= snapshot.confidence <= 1.0


def test_currency_reflects_supplied_articles():
    snapshot = _snapshot(articles=[_article(["T1499"])])
    assert snapshot.currency.intel_article_count == 1
    assert snapshot.currency.latest_intel_fetched_at == "2026-02-01T00:00:00Z"
    assert snapshot.currency.kb_fetched_at == "2026-01-01T00:00:00Z"


def test_no_index_degrades_to_an_empty_snapshot():
    snapshot = compute_snapshot(
        model=_model(), ruleset=RULESET, index=None, techniques_by_id={}, d3fend_catalog=[],
        cri_statements=[], regulatory_documents={}, tier=None,
        business_criticality=BusinessCriticality.HIGH, atlas_enabled=False, articles=[],
        kb_fetched_at=None, cri_fetched_at=None,
    )
    assert snapshot.paths == ()
    assert snapshot.adjudications == ()
    assert snapshot.confidence == 1.0
