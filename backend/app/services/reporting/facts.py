"""Builds the plain-text fact sheet handed to the LLM for narrative
generation (`narrative.py`) — every number/id in it comes straight from
`ReportData`, so it is, by construction, exactly the set of things the
narrative is allowed to mention.
"""

from __future__ import annotations

from app.services.reporting.models import ReportData


def build_facts_summary(data: ReportData, audience: str) -> str:
    lines = [
        f"Project: {data.project_name} (business criticality: {data.business_criticality})",
        f"Overall confidence: {data.confidence.overall_score:.0f}/100 ({data.confidence.band})",
    ]

    top_findings = sorted(data.risk_findings, key=lambda f: f.score, reverse=True)[:3]
    if top_findings:
        lines.append("Top risk findings:")
        for finding in top_findings:
            lines.append(
                f"- {finding.path_id}: score {finding.score:.3f}, entry {finding.entry_point} "
                f"-> target {finding.target}, techniques {list(finding.technique_ids)}"
            )
    else:
        lines.append("No attack paths were enumerated.")

    if data.has_cri:
        lines.append(f"CRI impact tier: {data.tier_justification}")
    else:
        lines.append("No CRI profile has been uploaded for this project.")

    if data.residual_risk is not None:
        lines.append(
            f"Residual risk after proposed mitigations: {data.residual_risk.risk_reduction:.3f} "
            f"reduction ({data.residual_risk.baseline_total_score:.3f} -> "
            f"{data.residual_risk.residual_total_score:.3f})"
        )

    if data.currency is not None:
        lines.append(
            f"Threat landscape currency: {data.currency.intel_article_count} intel article(s) applied, "
            f"KB fetched at {data.currency.kb_fetched_at}"
        )

    if audience == "technical":
        lines.append(f"Rejected (ungrounded) candidates: {len(data.rejection_log)}")
        lines.append(f"Assumptions made: {len(data.assumptions)}")

    return "\n".join(lines)
