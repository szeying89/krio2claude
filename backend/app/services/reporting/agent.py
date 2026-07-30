"""Reporting Agent (Task 22): generates one narrative per audience,
checking each inline against the real known-id set before surfacing it —
mirroring every other grounding split in this plan. `validate_reporting_fact_provenance`
is the orchestrator's central gate, independently re-scanning every
surfaced narrative rather than trusting the agent's own inline check.
"""

from __future__ import annotations

from typing import Any

from app.orchestrator.contracts import AgentContext, AgentSpec
from app.orchestrator.orchestrator import ValidationError
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.reporting.facts import build_facts_summary
from app.services.reporting.known_ids import collect_known_ids
from app.services.reporting.models import ReportData
from app.services.reporting.narrative import (
    AUDIENCE_CISO,
    AUDIENCE_EXECUTIVE,
    AUDIENCE_TECHNICAL,
    check_narrative_fact_provenance,
    generate_audience_narrative,
)

AGENT_NAME = "reporting"
AUDIENCES = (AUDIENCE_EXECUTIVE, AUDIENCE_CISO, AUDIENCE_TECHNICAL)


def build_reporting_agent(gateway: LLMGateway, params: CompletionParams) -> AgentSpec:
    """input_artifacts: `report_data: ReportData`."""

    def handler(ctx: AgentContext) -> dict[str, Any]:
        data: ReportData = ctx.input_artifacts["report_data"]
        known_ids = ctx.call_tool("reporting.collect_known_ids", collect_known_ids, data)

        narratives: dict[str, str] = {}
        rejection_log: list[dict[str, str]] = []

        for audience in AUDIENCES:
            facts = ctx.call_tool(
                "reporting.build_facts_summary", build_facts_summary, data, audience
            )
            narrative = ctx.call_tool(
                "reporting.generate_audience_narrative",
                generate_audience_narrative,
                gateway,
                params,
                audience,
                facts,
            )
            grounding = ctx.call_tool(
                "reporting.check_narrative_fact_provenance",
                check_narrative_fact_provenance,
                narrative,
                known_ids,
            )
            if not grounding.satisfied:
                rejection_log.append({"audience": audience, "detail": grounding.detail})
                continue
            narratives[audience] = narrative

        return {"report_data": data, "narratives": narratives, "rejection_log": rejection_log}

    return AgentSpec(
        name=AGENT_NAME,
        input_artifact_types=("report_data",),
        output_artifact_types=("report_data", "narratives", "rejection_log"),
        handler=handler,
        max_tool_calls=100,
    )


def validate_reporting_fact_provenance(agent_name: str, output_artifacts: dict[str, Any]) -> None:
    report_data = output_artifacts.get("report_data")
    narratives = output_artifacts.get("narratives", {})
    if report_data is None:
        return
    known_ids = collect_known_ids(report_data)
    for audience, narrative in narratives.items():
        result = check_narrative_fact_provenance(narrative, known_ids)
        if not result.satisfied:
            raise ValidationError(f"{agent_name}: {audience} narrative failed fact-provenance: {result.detail}")
