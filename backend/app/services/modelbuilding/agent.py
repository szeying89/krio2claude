"""Model-Building Agent: Task 1b `AgentSpec` wiring for Task 8's prose
extraction + Mermaid merge + completeness gate.

Every step the agent takes (parse a Mermaid block, call the LLM gateway
for prose extraction, merge, check completeness) goes through
`AgentContext.call_tool` — that's what keeps this auditable and centrally
gated even though the handler itself is just a function: the orchestrator
sees and can enforce budgets/validation on every one of these calls, not
just the agent's final output.
"""

from __future__ import annotations

from typing import Any

from app.orchestrator.contracts import AgentContext, AgentSpec
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.mermaid.errors import MermaidParseError
from app.services.mermaid.parser import parse_diagram
from app.services.modelbuilding.completeness import check_completeness
from app.services.modelbuilding.merge import ModelBuilder
from app.services.modelbuilding.models import Assumption
from app.services.modelbuilding.prose_extractor import extract_prose_entities

AGENT_NAME = "model_building"


def build_model_building_agent(gateway: LLMGateway, params: CompletionParams) -> AgentSpec:
    """`documents` in input_artifacts: a list of
    `{"document_id": str, "prose": str, "mermaid_sources": list[str]}`.
    `prose` uses its own line numbering (the document's extracted_prose,
    mermaid fences already stripped); each `mermaid_sources` entry uses its
    own block-relative line numbering — see `SourceSpan`'s docstring."""

    def handler(ctx: AgentContext) -> dict[str, Any]:
        documents: list[dict[str, Any]] = ctx.input_artifacts.get("documents", [])
        builder = ModelBuilder()

        for document in documents:
            document_id = document["document_id"]

            for mermaid_source in document.get("mermaid_sources", []):
                try:
                    diagram = ctx.call_tool("mermaid.parse_diagram", parse_diagram, mermaid_source)
                except MermaidParseError as exc:
                    builder.draft.assumptions.append(
                        Assumption(
                            kind="default",
                            subject_id=document_id,
                            message=f"a Mermaid block failed to parse ({exc}); modelling "
                            "proceeded from prose alone for this diagram",
                            source="mermaid",
                            confidence=1.0,
                            impact_if_wrong="structure this diagram would have contributed "
                            "is missing from the model",
                        )
                    )
                    continue
                ctx.call_tool(
                    "modelbuilding.add_diagram", builder.add_diagram, document_id, diagram
                )

            prose = document.get("prose", "")
            extraction = ctx.call_tool(
                "llm.extract_prose_entities", extract_prose_entities, gateway, prose, params
            )
            ctx.call_tool(
                "modelbuilding.add_prose_extraction",
                builder.add_prose_extraction,
                document_id,
                extraction,
            )

        findings = ctx.call_tool(
            "modelbuilding.check_completeness", check_completeness, builder.draft, builder
        )
        builder.draft.completeness_findings = findings

        return {"system_model_draft": builder.draft}

    return AgentSpec(
        name=AGENT_NAME,
        input_artifact_types=("design_document",),
        output_artifact_types=("system_model_draft",),
        handler=handler,
    )
