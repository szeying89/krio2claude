"""ATLAS parser.

ATLAS is NOT published as STIX — verified against the real feed at
mitre-atlas/atlas-data (dist/ATLAS.yaml): it's a custom YAML schema with its
own tactic/technique ID namespace (AML.TAxxxx / AML.Txxxx), and sub-techniques
appear as flat top-level entries carrying a `specializes` pointer to their
parent rather than being nested.
"""

from __future__ import annotations

from app.services.kb.models import TechniqueChunk


def parse_atlas_data(data: dict) -> list[TechniqueChunk]:
    chunks: list[TechniqueChunk] = []

    for matrix in data.get("matrices", []):
        tactic_names = {tactic["id"]: tactic["name"] for tactic in matrix.get("tactics", [])}

        for technique in matrix.get("techniques", []):
            if technique.get("object-type") != "technique":
                continue

            tactics = tuple(
                tactic_names.get(tactic_id, tactic_id)
                for tactic_id in technique.get("tactics", [])
            )

            chunks.append(
                TechniqueChunk(
                    id=technique["id"],
                    matrix="atlas",
                    name=technique.get("name", ""),
                    tactics=tactics,
                    description=technique.get("description", ""),
                    detection="",
                    platforms=(),
                    data_sources=(),
                )
            )

    return chunks
