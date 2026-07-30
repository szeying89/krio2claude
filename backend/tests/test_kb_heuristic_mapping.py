from app.services.kb.heuristic_mapping import HeuristicSource, infer_technique_mappings
from app.services.kb.models import TechniqueChunk


def _chunk(id_: str, name: str) -> TechniqueChunk:
    return TechniqueChunk(
        id=id_,
        matrix="enterprise",
        name=name,
        tactics=(),
        description="",
        detection="",
        platforms=(),
        data_sources=(),
    )


TECHNIQUES = [
    _chunk("T1556", "Multi-Factor Authentication Interception"),
    _chunk("T1071.004", "Application Layer Protocol: DNS"),
    _chunk("T1190", "Exploit Public-Facing Application"),
]


def test_matches_on_shared_significant_tokens():
    sources = [
        HeuristicSource(
            id="D3-MFA",
            name="Multi-factor Authentication",
            text="Requiring proof of two or more pieces of evidence to authenticate a user.",
        )
    ]
    mapping = infer_technique_mappings(sources, TECHNIQUES)

    assert "D3-MFA" in mapping
    ids = {m.technique_id for m in mapping["D3-MFA"]}
    assert "T1556" in ids
    matched = next(m for m in mapping["D3-MFA"] if m.technique_id == "T1556")
    assert "multi" in matched.matched_terms
    assert "factor" in matched.matched_terms
    assert "authentication" in matched.matched_terms


def test_below_threshold_produces_no_match():
    sources = [HeuristicSource(id="D3-X", name="Something Unrelated", text="totally different topic")]
    mapping = infer_technique_mappings(sources, TECHNIQUES)
    assert mapping.get("D3-X", []) == []
    # A source with zero matches must not appear as a key at all — not just
    # resolve to an empty list via .get() — so callers can trust len(mapping)
    # as a count of sources that actually matched something.
    assert "D3-X" not in mapping


def test_stopwords_do_not_count_toward_threshold():
    # Shares only generic/stopword-filtered terms with T1190's name/description;
    # must not produce a spurious match on "organization"/"security" alone.
    sources = [
        HeuristicSource(
            id="D3-GEN",
            name="Organization Security Program",
            text="A generic organizational security management process.",
        )
    ]
    mapping = infer_technique_mappings(sources, TECHNIQUES)
    assert mapping.get("D3-GEN", []) == []


def test_dns_traffic_analysis_matches_dns_technique_with_lowered_threshold():
    # Only "dns" is shared between the two names — a single short acronym
    # token. The default threshold (2) deliberately requires more than one
    # shared word to reduce noise; lowering it surfaces this weaker signal.
    sources = [
        HeuristicSource(
            id="D3-DNSTA",
            name="DNS Traffic Analysis",
            text="Analysis of domain name metadata to detect undesirable hosts.",
        )
    ]
    mapping = infer_technique_mappings(sources, TECHNIQUES, min_shared_tokens=1)
    ids = {m.technique_id for m in mapping["D3-DNSTA"]}
    assert "T1071.004" in ids


def test_deterministic_ordering_across_calls():
    sources = [
        HeuristicSource(id="D3-MFA", name="Multi-factor Authentication", text="authenticate a user")
    ]
    first = infer_technique_mappings(sources, TECHNIQUES)
    second = infer_technique_mappings(sources, TECHNIQUES)
    assert first == second
    assert [m.technique_id for m in first["D3-MFA"]] == sorted(
        m.technique_id for m in first["D3-MFA"]
    )


def test_custom_threshold_is_respected():
    sources = [HeuristicSource(id="D3-MFA", name="Multi-factor Authentication", text="")]
    strict = infer_technique_mappings(sources, TECHNIQUES, min_shared_tokens=3)
    loose = infer_technique_mappings(sources, TECHNIQUES, min_shared_tokens=1)
    assert len(loose["D3-MFA"]) >= len(strict.get("D3-MFA", []))
