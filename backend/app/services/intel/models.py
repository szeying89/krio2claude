"""Threat intelligence data model (Task 18)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True)
class AffectedProduct:
    vendor: str
    product: str
    version: str | None = None


@dataclass(frozen=True)
class ExtractedIntel:
    technique_ids: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()
    affected_products: tuple[AffectedProduct, ...] = ()
    actor: str | None = None
    targeted_sectors: tuple[str, ...] = field(default_factory=tuple)
    campaign_start: str | None = None
    campaign_end: str | None = None
    ttp_summary: str = ""
    source_credibility: str = "unknown"

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_ids": list(self.technique_ids),
            "cves": list(self.cves),
            "affected_products": [asdict(p) for p in self.affected_products],
            "actor": self.actor,
            "targeted_sectors": list(self.targeted_sectors),
            "campaign_start": self.campaign_start,
            "campaign_end": self.campaign_end,
            "ttp_summary": self.ttp_summary,
            "source_credibility": self.source_credibility,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> ExtractedIntel:
        return ExtractedIntel(
            technique_ids=tuple(data.get("technique_ids", [])),
            cves=tuple(data.get("cves", [])),
            affected_products=tuple(
                AffectedProduct(**p) for p in data.get("affected_products", [])
            ),
            actor=data.get("actor"),
            targeted_sectors=tuple(data.get("targeted_sectors", [])),
            campaign_start=data.get("campaign_start"),
            campaign_end=data.get("campaign_end"),
            ttp_summary=data.get("ttp_summary", ""),
            source_credibility=data.get("source_credibility", "unknown"),
        )
