"""Normalized knowledge-base data model.

Requirement 11 / Task 3: the KB is ATT&CK Enterprise + ATLAS only. ICS and
Mobile are not modelled at all — MATRICES below is the complete, closed set
permitted anywhere in the KB pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Matrix = Literal["enterprise", "atlas"]
MATRICES: tuple[Matrix, ...] = ("enterprise", "atlas")


@dataclass(frozen=True)
class TechniqueChunk:
    id: str
    matrix: Matrix
    name: str
    tactics: tuple[str, ...]
    description: str
    detection: str
    platforms: tuple[str, ...]
    data_sources: tuple[str, ...]
    relationships: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "matrix": self.matrix,
            "name": self.name,
            "tactics": list(self.tactics),
            "description": self.description,
            "detection": self.detection,
            "platforms": list(self.platforms),
            "data_sources": list(self.data_sources),
            "relationships": {k: list(v) for k, v in sorted(self.relationships.items())},
        }

    @staticmethod
    def from_dict(data: dict) -> TechniqueChunk:
        return TechniqueChunk(
            id=data["id"],
            matrix=data["matrix"],
            name=data["name"],
            tactics=tuple(data["tactics"]),
            description=data["description"],
            detection=data["detection"],
            platforms=tuple(data["platforms"]),
            data_sources=tuple(data["data_sources"]),
            relationships={k: tuple(v) for k, v in data.get("relationships", {}).items()},
        )


class UnsupportedDomainError(Exception):
    """Raised when a bundle contains an object outside the ATT&CK Enterprise
    or ATLAS domains — most notably ICS or Mobile. Rejected at load, not
    filtered out silently, so a wrong fixture or a misconfigured fetch URL
    fails loudly rather than quietly shipping partial/wrong coverage."""
