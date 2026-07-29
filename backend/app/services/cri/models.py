"""CRI Profile v2.2 data model.

Verified against a real CRI Profile v2.2 workbook: 318 diagnostic
statements, Tier-1=318 / Tier-2=311 / Tier-3=282 / Tier-4=208 applicable
statements (matching the workbook's own User Guide counts exactly).

`mapped_technique_ids` is intentionally always empty from workbook parsing
alone — the workbook carries no Profile->ATT&CK mapping. It's populated
later, if at all, by the heuristic bridge (app/services/kb/heuristic_mapping.py)
against a pinned KB snapshot, and any such link is a `mapping_inferred`
candidate, never presented as authoritative.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class RegulatoryReference:
    short_code: str
    count: int


@dataclass(frozen=True)
class RegulatoryDocument:
    short_code: str
    document_name: str
    issuing_organization: str
    region: str
    issue_date: str
    source_link: str
    status: str


@dataclass(frozen=True)
class EEEPackage:
    id: str
    name: str
    example_evidence: str


@dataclass(frozen=True)
class DiagnosticStatement:
    outline_id: str
    profile_id: str
    csf_path: tuple[str, ...]  # e.g. ("GOVERN", "Organizational Context", "Organizational Mission")
    name: str
    text: str
    applicable_tiers: tuple[int, ...]  # subset of (1, 2, 3, 4)
    regulatory_references: tuple[RegulatoryReference, ...] = ()
    subject_tags: tuple[str, ...] = ()
    eee_package_ids: tuple[str, ...] = ()
    mapped_technique_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "outline_id": self.outline_id,
            "profile_id": self.profile_id,
            "csf_path": list(self.csf_path),
            "name": self.name,
            "text": self.text,
            "applicable_tiers": list(self.applicable_tiers),
            "regulatory_references": [
                {"short_code": r.short_code, "count": r.count} for r in self.regulatory_references
            ],
            "subject_tags": list(self.subject_tags),
            "eee_package_ids": list(self.eee_package_ids),
            "mapped_technique_ids": list(self.mapped_technique_ids),
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> DiagnosticStatement:
        return DiagnosticStatement(
            outline_id=data["outline_id"],
            profile_id=data["profile_id"],
            csf_path=tuple(data["csf_path"]),
            name=data["name"],
            text=data["text"],
            applicable_tiers=tuple(data["applicable_tiers"]),
            regulatory_references=tuple(
                RegulatoryReference(r["short_code"], r["count"])
                for r in data.get("regulatory_references", [])
            ),
            subject_tags=tuple(data.get("subject_tags", [])),
            eee_package_ids=tuple(data.get("eee_package_ids", [])),
            mapped_technique_ids=tuple(data.get("mapped_technique_ids", [])),
        )


@dataclass(frozen=True)
class ControlObjectiveCatalog:
    version: str
    statements: tuple[DiagnosticStatement, ...]
    regulatory_documents: dict[str, RegulatoryDocument] = field(default_factory=dict)
    eee_packages: dict[str, EEEPackage] = field(default_factory=dict)
    unresolved_regulatory_references: tuple[str, ...] = ()

    def statements_for_tier(self, tier: int) -> tuple[DiagnosticStatement, ...]:
        return tuple(s for s in self.statements if tier in s.applicable_tiers)

    def by_profile_id(self, profile_id: str) -> DiagnosticStatement | None:
        for statement in self.statements:
            if statement.profile_id == profile_id:
                return statement
        return None
