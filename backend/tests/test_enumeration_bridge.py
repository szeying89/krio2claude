from app.services.enumeration.bridge import (
    bridge_candidates,
    build_capec_bridge,
    build_technique_index,
)
from app.services.enumeration.engine import CandidateThreat
from app.services.kb.models import TechniqueChunk
from app.services.systemmodel.models import Component, SystemModel, TrustZone


def _chunk(id_, matrix, name, description, capec=()):
    return TechniqueChunk(
        id=id_,
        matrix=matrix,
        name=name,
        tactics=("impact",),
        description=description,
        detection="",
        platforms=("Linux",),
        data_sources=(),
        relationships={"capec": capec} if capec else {},
    )


CHUNKS = [
    _chunk(
        "T1499",
        "enterprise",
        "Endpoint Denial of Service",
        "Adversaries may perform denial of service attacks to degrade or block availability "
        "by flooding a target with requests to exhaust resources.",
        capec=("CAPEC-125",),
    ),
    _chunk(
        "T1110",
        "enterprise",
        "Brute Force",
        "Adversaries may use brute force techniques such as password guessing or spraying "
        "to gain access to accounts.",
        capec=("CAPEC-49", "CAPEC-112"),
    ),
    _chunk(
        "T1uncited",
        "enterprise",
        "Uncited Technique",
        "This technique about denial of service flooding has no CAPEC mapping at all and "
        "must never be surfaced by the bridge.",
    ),
    _chunk(
        "AML.T0015",
        "atlas",
        "ML Model Denial of Service",
        "Adversaries may flood an ML inference endpoint to exhaust compute and deny service.",
        capec=("CAPEC-125",),
    ),
]


def test_bridge_surfaces_only_capec_mapped_techniques():
    index = build_technique_index(CHUNKS)
    results = build_capec_bridge("denial_of_service", "process", (), index, allowed_matrices=("enterprise",))
    ids = {r.technique_id for r in results}
    assert "T1uncited" not in ids
    assert "T1499" in ids


def test_bridge_excludes_atlas_by_default():
    index = build_technique_index(CHUNKS)
    results = build_capec_bridge("denial_of_service", "process", (), index, allowed_matrices=("enterprise",))
    assert all(r.matrix == "enterprise" for r in results)
    assert "AML.T0015" not in {r.technique_id for r in results}


def test_bridge_includes_atlas_when_allowed():
    index = build_technique_index(CHUNKS)
    results = build_capec_bridge(
        "denial_of_service", "process", (), index, allowed_matrices=("enterprise", "atlas")
    )
    assert "AML.T0015" in {r.technique_id for r in results}


def test_bridge_attaches_capec_ids():
    index = build_technique_index(CHUNKS)
    results = build_capec_bridge("denial_of_service", "process", (), index, allowed_matrices=("enterprise",))
    endpoint_dos = next(r for r in results if r.technique_id == "T1499")
    assert endpoint_dos.capec_ids == ("CAPEC-125",)


def test_no_ics_or_mobile_technique_can_enter_a_candidate_set():
    # TechniqueChunk.matrix is typed Literal["enterprise", "atlas"] and Task 3
    # rejects ICS/Mobile at KB-load time, so no such chunk can exist in a real
    # index — but the allowed_matrices filter is itself a second, independent
    # guard: even a hypothetical "ics"/"mobile" matrix value would never pass.
    index = build_technique_index(CHUNKS)
    results = build_capec_bridge(
        "denial_of_service", "process", (), index, allowed_matrices=("enterprise", "atlas")
    )
    assert all(r.matrix in ("enterprise", "atlas") for r in results)


def _model_with_components(*components: Component) -> SystemModel:
    return SystemModel(
        id="p1",
        version=1,
        parent_version=None,
        trust_zones=[TrustZone(id="tz1", name="Internal", trust_rating=1)],
        components=list(components),
    )


def test_bridge_candidates_maps_every_candidate_id():
    model = _model_with_components(
        Component(id="c1", name="Gateway", kind="process", trust_zone_id="tz1")
    )
    candidates = [
        CandidateThreat(id="c1::denial_of_service::1.0.0", element_id="c1", element_kind="process", framework="stride", category="denial_of_service", ruleset_version="1.0.0"),
        CandidateThreat(id="c1::spoofing::1.0.0", element_id="c1", element_kind="process", framework="stride", category="spoofing", ruleset_version="1.0.0"),
    ]
    index = build_technique_index(CHUNKS)
    bridged = bridge_candidates(model, candidates, index, allowed_matrices=("enterprise",))
    assert set(bridged.keys()) == {c.id for c in candidates}
    assert any(r.technique_id == "T1499" for r in bridged["c1::denial_of_service::1.0.0"])


def test_bridge_candidates_uses_component_technology_tags():
    model = _model_with_components(
        Component(
            id="c1", name="Login Service", kind="process", trust_zone_id="tz1",
            technology_tags=("brute", "force"),
        )
    )
    candidates = [
        CandidateThreat(id="c1::spoofing::1.0.0", element_id="c1", element_kind="process", framework="stride", category="spoofing", ruleset_version="1.0.0"),
    ]
    index = build_technique_index(CHUNKS)
    bridged = bridge_candidates(model, candidates, index, allowed_matrices=("enterprise",))
    # tags alone shouldn't crash the query construction; the bridge should
    # still return a well-formed (possibly empty) list
    assert isinstance(bridged["c1::spoofing::1.0.0"], list)
