"""Task 22's three audience renderers — plain markdown, all reading from
the same `ReportData` (so "shared numbers agree across audiences" is
true by construction: the confidence line, tier, and top-risk numbers are
formatted from the identical fields in every renderer, never
recomputed). Each takes an already-generated (and already
fact-checked) narrative string; rendering itself does no LLM work.
"""

from __future__ import annotations

from app.services.reporting.models import ReportData


def _confidence_line(data: ReportData) -> str:
    return f"**Confidence:** {data.confidence.overall_score:.0f}/100 ({data.confidence.band})"


def _limitations_section(data: ReportData) -> list[str]:
    lines = ["## Limitations"]
    if data.out_of_scope:
        for decl in data.out_of_scope:
            lines.append(f"- `{decl.subject_id}`: {decl.reason} ({decl.category})")
    else:
        lines.append("- No declared out-of-scope exclusions.")
    return lines


def render_executive_markdown(data: ReportData, narrative: str) -> str:
    lines = [
        f"# {data.project_name} — Executive Report",
        "",
        _confidence_line(data),
        "",
        "## Summary",
        narrative,
        "",
        "## Top Risks",
    ]
    top_findings = sorted(data.risk_findings, key=lambda f: f.score, reverse=True)[:5]
    if top_findings:
        for finding in top_findings:
            lines.append(
                f"- **{finding.path_id}** (score {finding.score:.3f}): "
                f"{finding.entry_point} -> {finding.target}"
            )
    else:
        lines.append("- No attack paths were enumerated.")

    if data.roadmap:
        lines.append("")
        lines.append("## Investment Asks")
        for phase in data.roadmap:
            lines.append(
                f"- Phase {phase.phase_number}: {len(phase.recommendations)} action(s), "
                f"risk reduction {phase.phase_risk_reduction:.3f}"
            )

    lines.append("")
    lines.extend(_limitations_section(data))
    return "\n".join(lines)


def render_ciso_markdown(data: ReportData, narrative: str) -> str:
    lines = [
        f"# {data.project_name} — CISO Report",
        "",
        _confidence_line(data),
        f"**Impact tier:** {data.tier_justification}",
        "",
        "## Summary",
        narrative,
        "",
        "## Risk Register",
    ]
    for finding in sorted(data.risk_findings, key=lambda f: f.score, reverse=True):
        lines.append(
            f"- {finding.path_id}: score {finding.score:.3f} "
            f"(likelihood {finding.factors.likelihood:.3f}, impact weight {finding.factors.impact_weight:.3f})"
        )

    lines.append("")
    lines.append("## CSF 2.0 Function Heatmap")
    for rollup in sorted(data.csf_rollup, key=lambda r: r.unsatisfied_density, reverse=True):
        lines.append(
            f"- {rollup.function}: {rollup.unsatisfied_statement_count}/"
            f"{rollup.in_tier_statement_count} unsatisfied ({rollup.unsatisfied_density:.0%})"
        )

    if data.has_cri:
        lines.append("")
        lines.append("## CRI Diagnostic Statement Gaps")
        for gap in data.gaps:
            if gap.cri_gap_statement_ids:
                lines.append(f"- {gap.technique_id}: gap statements {list(gap.cri_gap_statement_ids)}")
        lines.append("")
        lines.append("## Regulatory Exposure")
        for finding in data.risk_findings:
            for exposure in finding.regulatory_exposure:
                lines.append(f"- {finding.path_id}: {exposure.short_code} ({exposure.document_name})")

    if data.residual_risk is not None:
        lines.append("")
        lines.append("## Residual Risk")
        lines.append(
            f"- Baseline {data.residual_risk.baseline_total_score:.3f} -> "
            f"Residual {data.residual_risk.residual_total_score:.3f} "
            f"(reduction {data.residual_risk.risk_reduction:.3f})"
        )

    if data.roadmap:
        lines.append("")
        lines.append("## Roadmap")
        for phase in data.roadmap:
            lines.append(
                f"- Phase {phase.phase_number}: closes paths {list(phase.attack_paths_closed)}, "
                f"statements {list(phase.diagnostic_statements_closed)}"
            )

    if data.currency is not None:
        lines.append("")
        lines.append("## Threat Landscape Currency")
        lines.append(f"- Intel articles applied: {data.currency.intel_article_count}")
        lines.append(f"- KB fetched at: {data.currency.kb_fetched_at}")

    lines.append("")
    lines.extend(_limitations_section(data))
    return "\n".join(lines)


def render_technical_markdown(data: ReportData, narrative: str) -> str:
    lines = [
        f"# {data.project_name} — Technical Report",
        "",
        _confidence_line(data),
        "",
        "## Summary",
        narrative,
        "",
        "## System Model (DFD)",
        (
            f"Components: {len(data.model.components)}, Dataflows: {len(data.model.dataflows)}, "
            f"Trust zones: {len(data.model.trust_zones)}"
        ),
    ]
    for component in data.model.components:
        lines.append(f"- `{component.id}` ({component.kind}): {component.name}")
    for flow in data.model.dataflows:
        lines.append(f"- `{flow.id}`: {flow.source_id} -> {flow.destination_id}")

    lines.append("")
    lines.append("## Attack Paths")
    for finding in data.risk_findings:
        lines.append(
            f"- {finding.path_id}: {finding.entry_point} -> {finding.target} via "
            f"{list(finding.technique_ids)} (score {finding.score:.3f})"
        )

    lines.append("")
    lines.append("## Per-Entity Findings")
    for adjudication in data.adjudicated_threats:
        lines.append(
            f"- {adjudication.candidate_threat_id}: {adjudication.verdict} — {adjudication.rationale}"
        )

    if data.recommendations:
        lines.append("")
        lines.append("## Remediation Detail")
        for rec in data.recommendations:
            lines.append(f"- {rec.id} ({rec.technique_id}, {rec.d3fend_id}): {rec.guidance}")

    lines.append("")
    lines.append("## Appendix: Assumptions")
    for assumption in data.assumptions:
        lines.append(f"- `{assumption.subject_id}`: {assumption.message} (confidence {assumption.confidence:.2f})")

    lines.append("")
    lines.append("## Appendix: Rejected Candidates")
    for rejection in data.rejection_log:
        lines.append(f"- {rejection.candidate_threat_id}: {rejection.reason_code} — {rejection.detail}")

    lines.append("")
    lines.append("## Appendix: Not-Applicable Rationales")
    for adjudication in data.adjudicated_threats:
        if adjudication.verdict == "not_applicable":
            lines.append(f"- {adjudication.candidate_threat_id}: {adjudication.rationale}")

    if data.currency is not None:
        lines.append("")
        lines.append("## Appendix: Intel Provenance")
        lines.append(f"- {data.currency.intel_article_count} intel article(s) applied")

    lines.append("")
    lines.extend(_limitations_section(data))
    return "\n".join(lines)


RENDERERS = {
    "executive": render_executive_markdown,
    "ciso": render_ciso_markdown,
    "technical": render_technical_markdown,
}
