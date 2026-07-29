"""Rule-based relevance matching (Task 18): a deterministic tool, no LLM
involved, scoring an already-extracted article against a project's own
system model — technology tags and declared sector, exactly as the plan's
own demo text describes ("affects nginx 1.24 used by entity api-gateway").

Reuses `app.services.kb.heuristic_mapping.tokenize` for the same
lexical-overlap spirit as Tasks 3/4/15's heuristic matchers, but with a
1-shared-token threshold rather than 2: vendor/product names (e.g.
"nginx") are already highly specific, unlike the generic infosec
vocabulary those matchers guard against, so a single shared token is a
meaningful signal here.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.services.intel.models import ExtractedIntel
from app.services.kb.heuristic_mapping import tokenize
from app.services.systemmodel.models import SystemModel

PRODUCT_MATCH_SCORE = 0.7
SECTOR_MATCH_SCORE = 0.3


@dataclass(frozen=True)
class RelevanceResult:
    score: float
    reasons: tuple[str, ...]
    matched_entity_ids: tuple[str, ...]


def compute_relevance(
    extracted: ExtractedIntel,
    model: SystemModel,
    declared_sector: str | None = None,
) -> RelevanceResult:
    reasons: list[str] = []
    matched_entity_ids: set[str] = set()

    for product in extracted.affected_products:
        product_name = f"{product.vendor} {product.product} {product.version or ''}".strip()
        product_tokens = tokenize(product_name)
        if not product_tokens:
            continue
        for component in model.components:
            entity_tokens = tokenize(f"{component.name} {' '.join(component.technology_tags)}")
            if product_tokens & entity_tokens:
                matched_entity_ids.add(component.id)
                reasons.append(
                    f"affects {product_name}, used by entity {component.name!r} ({component.id})"
                )

    score = PRODUCT_MATCH_SCORE if matched_entity_ids else 0.0

    if declared_sector:
        sector_tokens = tokenize(declared_sector)
        if sector_tokens and any(
            sector_tokens & tokenize(sector) for sector in extracted.targeted_sectors
        ):
            score += SECTOR_MATCH_SCORE
            reasons.append(f"targets declared sector {declared_sector!r}")

    if not reasons:
        reasons.append("no matching entities, technology, or declared sector found in this model")

    return RelevanceResult(
        score=min(score, 1.0),
        reasons=tuple(reasons),
        matched_entity_ids=tuple(sorted(matched_entity_ids)),
    )
