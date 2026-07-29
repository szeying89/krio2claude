"""Per-gap mitigation recommendations (Task 17): for every unresolved
D3FEND gap on every technique in scope, generate one recommendation that
cites *exactly* that D3FEND id (assigned deterministically here, never
asked of the LLM, so it can never be hallucinated), names which of the
technique's own currently-unsatisfied CRI statements it also happens to
close (chosen only from a supplied allow-list of that technique's real
gap ids), and writes guidance naming only entities the technique's own
attack-path steps actually touch (again constrained to a supplied
allow-list, never free-form).

Every claim is checked twice: once inline by the agent itself
(`check_recommendation_grounding` below), and again, independently, by the
orchestrator's central `validate` gate in `agent.py` — mirroring Task 14's
`grounding.py`/`validate_enumeration_grounding` split, for the same
reason: a bug in the agent's own filter must not be the only thing
standing between a fabricated citation and a surfaced recommendation.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, Field

from app.services.kb.d3fend import D3fendTechnique
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.llm.prompt_template import PromptTemplate
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis

REASON_UNCITED_D3FEND = "uncited_d3fend"
REASON_UNCITED_CRI_STATEMENT = "uncited_cri_statement"
REASON_UNCITED_ENTITY = "uncited_entity"

DEFAULT_EFFORT = 3


@dataclass(frozen=True)
class MitigationRecommendation:
    id: str
    technique_id: str
    d3fend_id: str
    cri_statement_ids: tuple[str, ...]
    guidance: str
    referenced_entity_ids: tuple[str, ...]
    effort: int


@dataclass(frozen=True)
class RecommendationGroundingResult:
    satisfied: bool
    reason_code: str | None
    detail: str


def check_recommendation_grounding(
    rec: MitigationRecommendation,
    gap: TechniqueGapAnalysis,
    candidate_entity_ids: tuple[str, ...],
) -> RecommendationGroundingResult:
    if rec.d3fend_id not in gap.d3fend_gap_ids:
        return RecommendationGroundingResult(
            False,
            REASON_UNCITED_D3FEND,
            f"{rec.d3fend_id!r} is not an identified D3FEND gap for {gap.technique_id!r}",
        )

    fabricated_statements = set(rec.cri_statement_ids) - set(gap.cri_gap_statement_ids)
    if fabricated_statements:
        return RecommendationGroundingResult(
            False,
            REASON_UNCITED_CRI_STATEMENT,
            f"statement(s) {sorted(fabricated_statements)} are not unsatisfied CRI gaps "
            f"for {gap.technique_id!r}",
        )

    fabricated_entities = set(rec.referenced_entity_ids) - set(candidate_entity_ids)
    if fabricated_entities:
        return RecommendationGroundingResult(
            False,
            REASON_UNCITED_ENTITY,
            f"entity id(s) {sorted(fabricated_entities)} are not touched by {gap.technique_id!r}'s "
            "own attack-path steps",
        )

    return RecommendationGroundingResult(True, None, "")


class RecommendationExtraction(BaseModel):
    guidance: str
    referenced_entity_names: list[str] = Field(default_factory=list)
    satisfied_cri_statement_ids: list[str] = Field(default_factory=list)
    effort: int = Field(ge=1, le=5, default=DEFAULT_EFFORT)


RECOMMENDATION_TEMPLATE = PromptTemplate(
    name="mitigation_recommendation",
    version="1",
    template=(
        "You are writing one mitigation recommendation for a specific, already-identified "
        "security gap. Do not invent facts — only use the information given below.\n\n"
        "Technique: $technique_name ($technique_id)\n"
        "Description: $technique_description\n\n"
        "Countermeasure to recommend (you MUST recommend exactly this one, cited by name; "
        "do not propose any other countermeasure):\n"
        "$d3fend_name: $d3fend_definition\n\n"
        "Entities in the system model that this technique's attack path actually touches "
        "(name your guidance around ONLY these entities, by these exact names — do not "
        "mention any other entity):\n$entity_list\n\n"
        "Currently-unsatisfied CRI diagnostic statements for this technique (list, in "
        "satisfied_cri_statement_ids, ONLY the ids of the ones from this list that "
        "implementing the countermeasure above would actually satisfy — it is fine and "
        "expected to select none):\n$statement_list\n\n"
        "Write a short, specific implementation guidance paragraph (referenced_entity_names: "
        "the entity names your guidance actually names; effort: 1-5, where 1 is trivial "
        "configuration and 5 is a major engineering effort)."
    ),
)


def _entity_list(entity_names_by_id: dict[str, str], entity_ids: tuple[str, ...]) -> str:
    if not entity_ids:
        return "(none)"
    return "\n".join(f"- {entity_names_by_id[eid]}" for eid in entity_ids if eid in entity_names_by_id)


def _statement_list(statement_texts: dict[str, str]) -> str:
    if not statement_texts:
        return "(none)"
    return "\n".join(f"- {sid}: {text}" for sid, text in sorted(statement_texts.items()))


def generate_recommendation(
    gateway: LLMGateway,
    params: CompletionParams,
    gap: TechniqueGapAnalysis,
    technique_name: str,
    technique_description: str,
    d3fend: D3fendTechnique,
    candidate_statement_texts: dict[str, str],
    entity_names_by_id: dict[str, str],
    candidate_entity_ids: tuple[str, ...],
    recommendation_id: str,
) -> MitigationRecommendation:
    """One recommendation per (technique, D3FEND gap id) pair — `d3fend`
    must be the technique's own identified gap, never asked of the LLM."""
    result = gateway.complete_structured(
        RECOMMENDATION_TEMPLATE,
        {
            "technique_name": technique_name,
            "technique_id": gap.technique_id,
            "technique_description": technique_description,
            "d3fend_name": d3fend.name,
            "d3fend_definition": d3fend.definition,
            "entity_list": _entity_list(entity_names_by_id, candidate_entity_ids),
            "statement_list": _statement_list(candidate_statement_texts),
        },
        RecommendationExtraction,
        params,
    )
    extraction = result.output
    assert isinstance(extraction, RecommendationExtraction)

    name_to_id = {entity_names_by_id[eid]: eid for eid in candidate_entity_ids if eid in entity_names_by_id}
    referenced_entity_ids = tuple(
        sorted({name_to_id[name] for name in extraction.referenced_entity_names if name in name_to_id})
    )

    return MitigationRecommendation(
        id=recommendation_id,
        technique_id=gap.technique_id,
        d3fend_id=d3fend.id,
        cri_statement_ids=tuple(sorted(extraction.satisfied_cri_statement_ids)),
        guidance=extraction.guidance,
        referenced_entity_ids=referenced_entity_ids,
        effort=extraction.effort,
    )
