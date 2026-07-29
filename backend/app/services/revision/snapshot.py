"""Task 19: computes one `RevisionSnapshot` from a `SystemModel` plus
whatever intel articles apply — the full re-evaluation pipeline
(enumerate -> bridge -> ground -> adjudicate -> path-enumerate -> gap ->
risk-score), reusing Tasks 10-17's own deterministic tools directly, the
same way `app/api/mitigation.py`/`app/api/risk.py` already compose them
outside of any single `AgentSpec` — there is no existing agent that
already combines enumeration, path enumeration, and risk scoring in one
call, so this is fresh orchestration of already-built tools, not new
threat-modelling logic.
"""

from __future__ import annotations

from app.models.enums import BusinessCriticality
from app.services.cri.models import DiagnosticStatement
from app.services.enumeration.adjudication import Adjudication, adjudicate
from app.services.enumeration.attack_graph import build_attack_graph
from app.services.enumeration.bridge import BridgedTechnique, TechniqueIndex, build_capec_bridge
from app.services.enumeration.engine import CandidateThreat, enumerate_threats
from app.services.enumeration.grounding import check_grounding
from app.services.enumeration.path_enumeration import enumerate_paths
from app.services.enumeration.ruleset import Ruleset
from app.services.kb.d3fend import D3fendTechnique
from app.services.kb.models import TechniqueChunk
from app.services.mitigation.gap_analysis import compute_technique_gaps, techniques_in_paths
from app.services.mitigation.inventory import build_control_inventory
from app.services.revision.intel_integration import (
    IntelInput,
    build_intel_candidates,
    corroborated_uplift,
    intel_bridged_techniques,
    intel_widened_entities,
)
from app.services.revision.models import (
    AdjudicationSummary,
    CSFFunctionSummary,
    PathSummary,
    RevisionSnapshot,
    ThreatLandscapeCurrency,
)
from app.services.risk.register import build_csf_rollup, build_risk_register
from app.services.systemmodel.models import SystemModel


def _element_kind_and_tags(
    candidate: CandidateThreat, model: SystemModel
) -> tuple[str, tuple[str, ...]]:
    if candidate.element_kind == "dataflow":
        return "dataflow", ()
    component = next((c for c in model.components if c.id == candidate.element_id), None)
    return candidate.element_kind, (component.technology_tags if component else ())


def _confidence(adjudications: list[Adjudication], rejection_count: int) -> float:
    total = len(adjudications) + rejection_count
    if total == 0:
        return 1.0
    return len(adjudications) / total


def compute_snapshot(
    model: SystemModel,
    ruleset: Ruleset,
    index: TechniqueIndex | None,
    techniques_by_id: dict[str, TechniqueChunk],
    d3fend_catalog: list[D3fendTechnique],
    cri_statements: list[DiagnosticStatement],
    regulatory_documents: dict,
    tier: int | None,
    business_criticality: BusinessCriticality,
    atlas_enabled: bool,
    articles: list[IntelInput],
    kb_fetched_at: str | None,
    cri_fetched_at: str | None,
) -> RevisionSnapshot:
    currency = ThreatLandscapeCurrency(
        kb_fetched_at=kb_fetched_at,
        cri_fetched_at=cri_fetched_at,
        intel_article_count=len(articles),
        latest_intel_fetched_at=max((a.fetched_at for a in articles), default=None),
    )

    if index is None:
        return RevisionSnapshot(
            paths=(), adjudications=(), rejection_count=0, risk_total_score=0.0,
            csf_rollup=(), confidence=1.0, currency=currency,
        )

    allowed_matrices = ("enterprise", "atlas") if atlas_enabled else ("enterprise",)
    candidates = enumerate_threats(model, ruleset)
    dataflow_candidates = [
        c for c in candidates if c.element_kind == "dataflow" and c.framework == "stride"
    ]
    graph = build_attack_graph(model, dataflow_candidates, index, allowed_matrices=allowed_matrices)
    reachable_entity_ids = {n.entity_id for n in graph.graph.nodes}

    intel_uplift = corroborated_uplift(articles, index)
    path_result = enumerate_paths(graph, model, intel_uplift=intel_uplift or None)

    adjudications: list[Adjudication] = []
    rejection_count = 0
    existing_candidate_keys: set[tuple[str, str]] = set()

    for candidate in candidates:
        element_kind, tags = _element_kind_and_tags(candidate, model)
        bridged: list[BridgedTechnique] = build_capec_bridge(
            candidate.category, element_kind, tags, index, allowed_matrices
        )
        for technique in bridged:
            existing_candidate_keys.add((candidate.element_id, technique.technique_id))

        grounding = check_grounding(candidate, model, bridged)
        if not grounding.satisfied:
            rejection_count += 1
            continue

        widened = set(reachable_entity_ids)
        for technique in bridged:
            widened |= intel_widened_entities(articles, technique.technique_id)

        adjudications.append(adjudicate(candidate, model, bridged, widened))

    for intel_candidate in build_intel_candidates(articles, existing_candidate_keys):
        technique_id = intel_candidate.id.split("::")[-1]
        bridged = intel_bridged_techniques(technique_id, index)
        grounding = check_grounding(intel_candidate, model, bridged)
        if not grounding.satisfied:
            rejection_count += 1
            continue
        adjudications.append(adjudicate(intel_candidate, model, bridged, reachable_entity_ids))

    technique_ids_in_paths = techniques_in_paths(path_result)
    inventory = build_control_inventory(model.declared_controls, d3fend_catalog, cri_statements)
    gaps = compute_technique_gaps(technique_ids_in_paths, techniques_by_id, inventory, cri_statements, tier)
    risk_register = build_risk_register(
        path_result, gaps, business_criticality, tier, cri_statements, regulatory_documents
    )

    path_summaries = tuple(
        PathSummary(
            id=path.id,
            entry_point=path.entry_point,
            target=path.target,
            technique_ids=tuple(dict.fromkeys(step.technique_id for step in path.steps)),
            aggregate_likelihood=path.aggregate_likelihood,
        )
        for path in path_result.paths
    )
    adjudication_summaries = tuple(
        AdjudicationSummary(
            candidate_threat_id=a.candidate_threat_id, verdict=a.verdict, citation_score=a.citation_score
        )
        for a in adjudications
    )
    csf_rollup = tuple(
        CSFFunctionSummary(function=r.function, unsatisfied_density=r.unsatisfied_density)
        for r in build_csf_rollup(gaps)
    )
    confidence = _confidence(adjudications, rejection_count)

    return RevisionSnapshot(
        paths=path_summaries,
        adjudications=adjudication_summaries,
        rejection_count=rejection_count,
        risk_total_score=sum(f.score for f in risk_register.findings),
        csf_rollup=csf_rollup,
        confidence=confidence,
        currency=currency,
    )
