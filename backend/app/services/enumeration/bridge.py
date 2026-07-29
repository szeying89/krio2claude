"""CAPEC bridge (Task 11): (STRIDE/LINDDUN category, element kind,
technology tags) -> CAPEC patterns -> ATT&CK techniques, cross-checked
against retrieval.

Rather than a fabricated (category, element_kind) -> specific-CAPEC-ID
lookup table (a real risk of inventing identifiers I'm not certain are
correct), this bridge: builds a natural-language query from a small,
versioned category -> search-terms table plus the element's own
technology tags; runs it through Task 5's hybrid retrieval against the
live KB snapshot's real technique corpus; and keeps only results that (a)
are in an allowed matrix (Enterprise always, ATLAS only once
user-confirmed — see `atlas_detector.py`) and (b) carry a real CAPEC
cross-reference, sourced from Task 3's own CAPEC STIX
`external_references` parsing, never invented here. The surviving CAPEC
ids are attached to each technique as its bridge citation.

Enterprise/ATLAS-only is also a structural guarantee, not just a runtime
filter: `TechniqueChunk.matrix` (app/services/kb/models.py) is typed
`Literal["enterprise", "atlas"]` and Task 3 rejects ICS/Mobile content at
KB-load time — no such technique can exist in the corpus this bridge
searches, let alone survive the `allowed_matrices` filter below.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.enumeration.engine import CandidateThreat
from app.services.kb.models import TechniqueChunk
from app.services.retrieval.service import RetrievalCollection, build_technique_collection
from app.services.systemmodel.models import SystemModel

CATEGORY_SEARCH_TERMS: dict[str, tuple[str, ...]] = {
    "spoofing": ("spoofing", "impersonation", "identity", "phishing"),
    "tampering": ("tampering", "modify data", "man in the middle", "integrity"),
    "repudiation": ("log", "audit", "indicator removal", "clear logs"),
    "information_disclosure": ("information disclosure", "exfiltration", "sniffing", "collection"),
    "denial_of_service": ("denial of service", "flood", "resource exhaustion"),
    "elevation_of_privilege": ("privilege escalation", "exploitation", "elevate privileges"),
    "linkability": ("linkability", "correlation", "tracking"),
    "identifiability": ("identifiability", "de-anonymization", "re-identification"),
    "non_repudiation": ("non-repudiation", "logging", "accountability"),
    "detectability": ("detectability", "existence disclosure"),
    "disclosure_of_information": ("information disclosure", "data leak", "privacy breach"),
    "unawareness": ("unawareness", "consent", "notice"),
    "non_compliance": ("non-compliance", "policy violation", "regulation"),
}


@dataclass(frozen=True)
class BridgedTechnique:
    technique_id: str
    technique_name: str
    matrix: str
    capec_ids: tuple[str, ...]
    fused_score: float


@dataclass(frozen=True)
class TechniqueIndex:
    collection: RetrievalCollection
    capec_by_technique: dict[str, tuple[str, ...]]
    name_by_technique: dict[str, str]
    matrix_by_technique: dict[str, str]


def build_technique_index(chunks: list[TechniqueChunk]) -> TechniqueIndex:
    return TechniqueIndex(
        collection=build_technique_collection(chunks),
        capec_by_technique={c.id: c.relationships.get("capec", ()) for c in chunks},
        name_by_technique={c.id: c.name for c in chunks},
        matrix_by_technique={c.id: c.matrix for c in chunks},
    )


def build_capec_bridge(
    category: str,
    element_kind: str,
    technology_tags: tuple[str, ...],
    index: TechniqueIndex,
    allowed_matrices: tuple[str, ...] = ("enterprise",),
    top_k: int = 5,
) -> list[BridgedTechnique]:
    terms = CATEGORY_SEARCH_TERMS.get(category, (category,))
    query = " ".join([*terms, element_kind.replace("_", " "), *technology_tags])

    # search a wider pool than top_k since matrix/CAPEC filtering happens
    # after retrieval, not before
    results = index.collection.search(query, top_k=max(top_k * 6, 30))

    bridged: list[BridgedTechnique] = []
    for result in results:
        matrix = index.matrix_by_technique.get(result.doc_id)
        if matrix not in allowed_matrices:
            continue
        capec_ids = index.capec_by_technique.get(result.doc_id, ())
        if not capec_ids:
            continue
        bridged.append(
            BridgedTechnique(
                technique_id=result.doc_id,
                technique_name=index.name_by_technique.get(result.doc_id, result.doc_id),
                matrix=matrix,
                capec_ids=capec_ids,
                fused_score=result.fused_score,
            )
        )
        if len(bridged) >= top_k:
            break
    return bridged


def bridge_candidates(
    model: SystemModel,
    candidates: list[CandidateThreat],
    index: TechniqueIndex,
    allowed_matrices: tuple[str, ...] = ("enterprise",),
    top_k: int = 5,
) -> dict[str, list[BridgedTechnique]]:
    """Bridges every candidate at once, reusing each (element, category)
    query's result across candidates that share one (STRIDE and LINDDUN
    findings on the same element ask the same bridge question twice)."""
    tags_by_element: dict[str, tuple[str, ...]] = {c.id: c.technology_tags for c in model.components}
    cache: dict[tuple[str, str], list[BridgedTechnique]] = {}
    result: dict[str, list[BridgedTechnique]] = {}

    for candidate in candidates:
        key = (candidate.element_id, candidate.category)
        if key not in cache:
            tags = tags_by_element.get(candidate.element_id, ())
            cache[key] = build_capec_bridge(
                candidate.category,
                candidate.element_kind,
                tags,
                index,
                allowed_matrices=allowed_matrices,
                top_k=top_k,
            )
        result[candidate.id] = cache[key]

    return result
