"""Task 21's adversarial critique: the LLM only ever writes severity and
rationale narrative for an already-identified, already-cited
`CandidateIssue` (`critique_detectors.py`) — it is never asked to name
which model element or CRI statement is at issue, mirroring Task 17's
D3FEND-id split. `check_review_item_grounding` independently re-verifies
every citation against the real model/known-statement-id sets, exactly
like every other grounding check in this plan; a finding whose citations
don't resolve to something real is rejected, never surfaced.
"""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, Field

from app.services.assurance.critique_detectors import CandidateIssue
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.llm.prompt_template import PromptTemplate
from app.services.systemmodel.models import SystemModel

ALLOWED_SEVERITIES = ("low", "medium", "high", "critical")
DEFAULT_SEVERITY = "medium"

REASON_NO_CITATION = "no_citation"
REASON_UNCITED_ELEMENT = "uncited_element"
REASON_UNCITED_STATEMENT = "uncited_statement"
REASON_INVALID_SEVERITY = "invalid_severity"


@dataclass(frozen=True)
class ReviewItem:
    id: str
    category: str
    severity: str
    rationale: str
    cited_element_ids: tuple[str, ...]
    cited_statement_ids: tuple[str, ...]


@dataclass(frozen=True)
class ReviewItemGroundingResult:
    satisfied: bool
    reason_code: str | None
    detail: str


def _known_element_ids(model: SystemModel) -> set[str]:
    return (
        {c.id for c in model.components}
        | {f.id for f in model.dataflows}
        | {ctrl.id for ctrl in model.declared_controls}
    )


def check_review_item_grounding(
    item: ReviewItem, model: SystemModel, known_statement_ids: set[str]
) -> ReviewItemGroundingResult:
    if not item.cited_element_ids and not item.cited_statement_ids:
        return ReviewItemGroundingResult(
            False, REASON_NO_CITATION, "cites no model element or CRI statement id at all"
        )

    fabricated_elements = set(item.cited_element_ids) - _known_element_ids(model)
    if fabricated_elements:
        return ReviewItemGroundingResult(
            False,
            REASON_UNCITED_ELEMENT,
            f"element id(s) {sorted(fabricated_elements)} do not exist in the model",
        )

    fabricated_statements = set(item.cited_statement_ids) - known_statement_ids
    if fabricated_statements:
        return ReviewItemGroundingResult(
            False,
            REASON_UNCITED_STATEMENT,
            f"statement id(s) {sorted(fabricated_statements)} are not known CRI statements",
        )

    if item.severity not in ALLOWED_SEVERITIES:
        return ReviewItemGroundingResult(
            False, REASON_INVALID_SEVERITY, f"severity {item.severity!r} is not one of {ALLOWED_SEVERITIES}"
        )

    return ReviewItemGroundingResult(True, None, "")


class CritiqueExtraction(BaseModel):
    severity: str = Field(default=DEFAULT_SEVERITY)
    rationale: str = ""


CRITIQUE_TEMPLATE = PromptTemplate(
    name="critique_review_item",
    version="1",
    template=(
        "You are red-teaming a finished threat model. Below is one already-identified issue "
        "(category: $category) with the real facts behind it — do not invent any additional "
        "facts, ids, or claims beyond what is given.\n\n"
        "$context\n\n"
        "Assess: severity (\"low\", \"medium\", \"high\", or \"critical\") and a short rationale "
        "explaining why a human reviewer should care about this."
    ),
)


def generate_review_item(
    gateway: LLMGateway,
    params: CompletionParams,
    candidate: CandidateIssue,
    item_id: str,
) -> ReviewItem:
    result = gateway.complete_structured(
        CRITIQUE_TEMPLATE,
        {"category": candidate.category, "context": candidate.context},
        CritiqueExtraction,
        params,
    )
    extraction = result.output
    assert isinstance(extraction, CritiqueExtraction)

    return ReviewItem(
        id=item_id,
        category=candidate.category,
        severity=extraction.severity,
        rationale=extraction.rationale,
        cited_element_ids=candidate.cited_element_ids,
        cited_statement_ids=candidate.cited_statement_ids,
    )
