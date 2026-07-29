"""The fact-provenance boundary for Task 22's narrative generation: every
id a report's LLM-authored narrative could legitimately mention, derived
directly from the same `ReportData` the report renders — never a
separately-maintained list that could drift from what's actually in the
report.
"""

from __future__ import annotations

from app.services.reporting.models import ReportData


def collect_known_ids(data: ReportData) -> set[str]:
    ids: set[str] = set()
    ids.update(c.id for c in data.model.components)
    ids.update(f.id for f in data.model.dataflows)
    ids.update(z.id for z in data.model.trust_zones)
    ids.update(a.id for a in data.model.assets)
    ids.update(ctrl.id for ctrl in data.model.declared_controls)

    ids.update(finding.path_id for finding in data.risk_findings)
    for finding in data.risk_findings:
        ids.update(finding.technique_ids)

    ids.update(g.technique_id for g in data.gaps)
    for g in data.gaps:
        ids.update(g.cri_in_tier_statement_ids)
        ids.update(g.cri_gap_statement_ids)
        ids.update(g.d3fend_required_ids)
        ids.update(g.d3fend_gap_ids)

    ids.update(a.candidate_threat_id for a in data.adjudicated_threats)
    ids.update(r.candidate_threat_id for r in data.rejection_log)
    ids.update(rec.id for rec in data.recommendations)
    ids.update(rec.d3fend_id for rec in data.recommendations)

    return ids
