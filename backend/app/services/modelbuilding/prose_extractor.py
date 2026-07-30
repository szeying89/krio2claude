"""LLM-backed prose entity extraction (Model-Building Agent, Requirement:
"extraction of components, flows, assets, actors, trust zones, and
declared controls with source span citations").

This is the one genuinely LLM-reasoning step in Task 8 — unlike the
Mermaid parser (Task 6) or the STRIDE engine (Task 10), free prose has no
fixed grammar to parse deterministically. It goes through the Task 7
gateway like every other agent call: pinned temperature 0, versioned
prompt template, strict Pydantic schema validation with bounded repair
retries, content-addressed caching. Every extracted item must cite a
confidence and a line-range source span into the numbered prose the model
was shown, so nothing enters the model ungrounded.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.llm.prompt_template import PromptTemplate


class ProseSourceSpan(BaseModel):
    start_line: int
    end_line: int


class ProseComponent(BaseModel):
    name: str
    kind: str  # "process" | "datastore"
    technology_tags: list[str] = Field(default_factory=list)
    confidence: float
    source_span: ProseSourceSpan


class ProseActor(BaseModel):
    name: str
    confidence: float
    source_span: ProseSourceSpan


class ProseFlow(BaseModel):
    source_name: str
    target_name: str
    label: str = ""
    protocol: str | None = None
    authenticated: bool | None = None
    encrypted: bool | None = None
    confidence: float
    source_span: ProseSourceSpan


class ProseAsset(BaseModel):
    name: str
    classification: str | None = None
    owner_name: str | None = None
    confidence: float
    source_span: ProseSourceSpan


class ProseTrustZone(BaseModel):
    name: str
    member_names: list[str] = Field(default_factory=list)
    confidence: float
    source_span: ProseSourceSpan


class ProseDeclaredControl(BaseModel):
    name: str
    applies_to_names: list[str] = Field(default_factory=list)
    confidence: float
    source_span: ProseSourceSpan


class ProseExtractionResult(BaseModel):
    components: list[ProseComponent] = Field(default_factory=list)
    actors: list[ProseActor] = Field(default_factory=list)
    flows: list[ProseFlow] = Field(default_factory=list)
    assets: list[ProseAsset] = Field(default_factory=list)
    trust_zones: list[ProseTrustZone] = Field(default_factory=list)
    declared_controls: list[ProseDeclaredControl] = Field(default_factory=list)


PROSE_EXTRACTION_TEMPLATE = PromptTemplate(
    name="prose_entity_extraction",
    version="1",
    template=(
        "You are extracting a threat-modelling system inventory from a software "
        "design document. Read the line-numbered document below and identify only "
        "what is actually stated or clearly implied by the text — never invent an "
        "element that isn't evidenced.\n\n"
        "Extract:\n"
        "- components: internal processes or data stores (kind: \"process\" or "
        "\"datastore\")\n"
        "- actors: external entities/users/systems that interact with the system\n"
        "- flows: data flows between named components/actors, with protocol, "
        "authentication, and encryption if stated\n"
        "- assets: named pieces of data, with a classification if stated\n"
        "- trust_zones: named security/network boundaries and their members\n"
        "- declared_controls: security controls the document says are in place, "
        "and what they apply to\n\n"
        "Every item MUST include a confidence (0.0-1.0) and a source_span "
        "(start_line/end_line) citing exactly where in the document below it is "
        "described.\n\n"
        "Document (line-numbered):\n$numbered_prose\n"
    ),
)


def number_lines(prose: str) -> str:
    return "\n".join(f"{i}: {line}" for i, line in enumerate(prose.splitlines(), start=1))


def extract_prose_entities(
    gateway: LLMGateway,
    prose: str,
    params: CompletionParams,
    kb_snapshot_hash: str | None = None,
) -> ProseExtractionResult:
    if not prose.strip():
        return ProseExtractionResult()
    numbered = number_lines(prose)
    result = gateway.complete_structured(
        PROSE_EXTRACTION_TEMPLATE,
        {"numbered_prose": numbered},
        ProseExtractionResult,
        params,
        kb_snapshot_hash=kb_snapshot_hash,
    )
    output = result.output
    assert isinstance(output, ProseExtractionResult)
    return output
