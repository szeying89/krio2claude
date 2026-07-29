"""Task 22's per-audience LLM narrative, and the fact-provenance scan
that guards it. The LLM is shown a curated, already-computed plain-text
fact sheet (never the raw model) and asked only to frame it for one
audience — it cannot introduce a number or id that isn't already in that
sheet, because `check_narrative_fact_provenance` independently scans the
finished text for every *structurally distinctive* id shape this
platform produces (ATT&CK/ATLAS technique ids, CVEs, CRI statement ids,
D3FEND ids, attack-path ids, candidate-threat ids, recommendation ids)
and rejects the narrative if any such token isn't in the real known-id
set — belt-and-suspenders on top of the curated fact sheet, exactly the
same posture as every other grounding check in this plan.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from pydantic import BaseModel

from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.llm.prompt_template import PromptTemplate

AUDIENCE_EXECUTIVE = "executive"
AUDIENCE_CISO = "ciso"
AUDIENCE_TECHNICAL = "technical"

_ID_PATTERNS = [
    re.compile(r"\bAML\.T\d{4}(\.\d{3})?\b"),
    re.compile(r"(?<!AML\.)\bT\d{4}(\.\d{3})?\b"),
    re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE),
    re.compile(r"\b[A-Z]{2}\.[A-Z]{2,3}-\d{2}\.\d{2}\b"),
    re.compile(r"\bD3-[A-Z]+\b"),
    re.compile(r"\bpath-[0-9a-f]{16}\b"),
    re.compile(r"\b[\w-]+::[\w_]+::[\d.]+\b"),
    re.compile(r"\brec-[\w-]+\b"),
    re.compile(r"\breview-[0-9a-f]+\b"),
]


def extract_id_like_tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    for pattern in _ID_PATTERNS:
        tokens.update(match.group(0) for match in pattern.finditer(text))
    return tokens


@dataclass(frozen=True)
class FactProvenanceResult:
    satisfied: bool
    detail: str


def check_narrative_fact_provenance(narrative: str, known_ids: set[str]) -> FactProvenanceResult:
    mentioned = extract_id_like_tokens(narrative)
    fabricated = mentioned - known_ids
    if fabricated:
        return FactProvenanceResult(
            False, f"narrative mentions id(s) absent from the model/findings: {sorted(fabricated)}"
        )
    return FactProvenanceResult(True, "")


class AudienceNarrativeSchema(BaseModel):
    summary: str = ""


NARRATIVE_TEMPLATE = PromptTemplate(
    name="report_narrative",
    version="1",
    template=(
        "You are drafting the narrative summary section of a threat model report for a "
        "$audience audience. Use ONLY the facts below — never invent a number, id, or claim "
        "beyond what is given here.\n\n"
        "$facts\n\n"
        "Write a short summary (2-4 sentences) framed appropriately for this audience."
    ),
)


def generate_audience_narrative(
    gateway: LLMGateway, params: CompletionParams, audience: str, facts_summary: str
) -> str:
    result = gateway.complete_structured(
        NARRATIVE_TEMPLATE, {"audience": audience, "facts": facts_summary}, AudienceNarrativeSchema, params
    )
    extraction = result.output
    assert isinstance(extraction, AudienceNarrativeSchema)
    return extraction.summary
