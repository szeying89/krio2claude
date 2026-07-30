"""Task 22's CSV findings register — one row per attack-path finding,
carrying exactly the columns the plan names for GRC import: finding id,
technique id(s), CRI statement id(s), CSF function(s), and risk score.
Multi-valued cells are `;`-joined, the standard convention for a single
CSV cell carrying several ids; `parse_csv` is the exact inverse, used to
prove "CSV round-trips IDs and statement references" in tests.
"""

from __future__ import annotations

import csv
import io
from typing import Any

from app.services.reporting.models import ReportData

CSV_FIELDNAMES = ["finding_id", "technique_ids", "cri_statement_ids", "csf_functions", "risk_score"]


def export_csv(data: ReportData) -> str:
    gaps_by_technique = {g.technique_id: g for g in data.gaps}
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_FIELDNAMES)
    writer.writeheader()

    for finding in data.risk_findings:
        cri_statement_ids: set[str] = set()
        for technique_id in finding.technique_ids:
            gap = gaps_by_technique.get(technique_id)
            if gap is not None:
                cri_statement_ids.update(gap.cri_in_tier_statement_ids)

        writer.writerow(
            {
                "finding_id": finding.path_id,
                "technique_ids": ";".join(finding.technique_ids),
                "cri_statement_ids": ";".join(sorted(cri_statement_ids)),
                "csf_functions": ";".join(finding.csf_functions),
                "risk_score": f"{finding.score:.6f}",
            }
        )
    return buffer.getvalue()


def parse_csv(text: str) -> list[dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    rows = []
    for row in reader:
        rows.append(
            {
                "finding_id": row["finding_id"],
                "technique_ids": [t for t in row["technique_ids"].split(";") if t],
                "cri_statement_ids": [s for s in row["cri_statement_ids"].split(";") if s],
                "csf_functions": [c for c in row["csf_functions"].split(";") if c],
                "risk_score": float(row["risk_score"]),
            }
        )
    return rows
