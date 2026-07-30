"""Bridges Task 18's intel extraction/relevance into Task 19's
re-evaluation. Two distinct, independent effects, matching the plan's own
two verbs:

- **Corroboration** (likelihood): a technique the KB corpus already
  recognizes, named in an article, gets a likelihood uplift wherever it
  already appears in the attack graph — Task 13's `intel_uplift` seam,
  finally fed real data.
- **Contradiction** (reachability): an article naming both a technique
  *and* a real model entity it affects (via Task 18's relevance match)
  is treated as first-hand evidence that entity is reachable by that
  technique today, regardless of what the attack graph's own topology
  computed — this is exactly the "new information" Task 14's
  `InvalidationCondition` describes as capable of overturning a
  `not_applicable` verdict. It can only ever widen *reachability*, never
  scope: `out_of_scope_status_change` conditions are untouched by design,
  since intel has no channel to change project scope (Task 18's gate
  forbids it structurally).

Both effects, and any brand-new intel-derived candidate threat, must
still clear the exact same `check_grounding` gate as anything else in
this plan — a technique id the KB corpus doesn't recognize produces no
`BridgedTechnique`, so it is rejected on `no_citation` like any other
ungrounded claim ("intel-only claims without ATT&CK/ATLAS grounding never
become findings").
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.enumeration.bridge import BridgedTechnique, TechniqueIndex
from app.services.enumeration.engine import CandidateThreat
from app.services.intel.models import ExtractedIntel
from app.services.intel.relevance import RelevanceResult

DEFAULT_UPLIFT_FACTOR = 3.0
INTEL_CITATION_SCORE = 1.0


@dataclass(frozen=True)
class IntelInput:
    content_hash: str
    fetched_at: str
    extracted: ExtractedIntel
    relevance: RelevanceResult


def corroborated_uplift(
    articles: list[IntelInput],
    index: TechniqueIndex,
    uplift_factor: float = DEFAULT_UPLIFT_FACTOR,
) -> dict[str, float]:
    """Only techniques the KB corpus itself recognizes are eligible —
    corroborating an unknown id is meaningless; the max uplift wins if
    multiple articles name the same technique."""
    uplift: dict[str, float] = {}
    for article in articles:
        for technique_id in article.extracted.technique_ids:
            if technique_id not in index.name_by_technique:
                continue
            uplift[technique_id] = max(uplift.get(technique_id, 1.0), uplift_factor)
    return uplift


def intel_widened_entities(articles: list[IntelInput], technique_id: str) -> set[str]:
    """Every entity id at least one article both (a) names as affected by
    `technique_id` and (b) matches to a real model entity via Task 18's
    own relevance scoring."""
    widened: set[str] = set()
    for article in articles:
        if technique_id in article.extracted.technique_ids:
            widened.update(article.relevance.matched_entity_ids)
    return widened


def build_intel_candidates(
    articles: list[IntelInput],
    existing_candidate_keys: set[tuple[str, str]],
) -> list[CandidateThreat]:
    """One synthetic candidate per (entity, technique) pair an article
    corroborates via a real relevance match, skipping any pair already
    covered by an existing STRIDE/LINDDUN candidate for that element."""
    seen: set[tuple[str, str]] = set()
    candidates: list[CandidateThreat] = []
    for article in articles:
        for technique_id in article.extracted.technique_ids:
            for entity_id in article.relevance.matched_entity_ids:
                key = (entity_id, technique_id)
                if key in existing_candidate_keys or key in seen:
                    continue
                seen.add(key)
                candidates.append(
                    CandidateThreat(
                        id=f"intel::{entity_id}::{technique_id}",
                        element_id=entity_id,
                        element_kind="component",
                        framework="intel",
                        category="intel_reported",
                        ruleset_version="intel",
                    )
                )
    return candidates


def intel_bridged_techniques(technique_id: str, index: TechniqueIndex) -> list[BridgedTechnique]:
    """Constructs a citation directly from the KB corpus for an
    intel-derived candidate — never fabricated: if the technique isn't in
    `index`, this returns an empty list, which fails `check_grounding` on
    `no_citation` exactly like any other ungrounded candidate."""
    name = index.name_by_technique.get(technique_id)
    if name is None:
        return []
    return [
        BridgedTechnique(
            technique_id=technique_id,
            technique_name=name,
            matrix=index.matrix_by_technique.get(technique_id, "enterprise"),
            capec_ids=index.capec_by_technique.get(technique_id, ()),
            fused_score=INTEL_CITATION_SCORE,
        )
    ]
