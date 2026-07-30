"""D3FEND technique catalog parser.

Parses D3FEND's real technique taxonomy export (verified against a live
CSV pull): ID, D3FEND Tactic, D3FEND Technique, D3FEND Technique Level 0,
D3FEND Technique Level 1, Definition. This is a *catalog* (ID, tactic,
name, hierarchy, definition) — the export carries no ATT&CK mapping
column, so any D3FEND->ATT&CK relationship has to come from
app/services/kb/heuristic_mapping.py rather than an authoritative source.

Depth in the hierarchy is encoded by which of the three name columns is
populated (Technique / Level 0 / Level 1), not by an explicit parent-ID
column; a row's parent is the nearest preceding row at the next-shallower
depth, and starting a new node at a given depth invalidates any previously
tracked descendant branches at that depth or deeper.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass

REQUIRED_HEADERS = [
    "ID",
    "D3FEND Tactic",
    "D3FEND Technique",
    "D3FEND Technique Level 0",
    "D3FEND Technique Level 1",
    "Definition",
]


class D3fendParseError(Exception):
    pass


@dataclass(frozen=True)
class D3fendTechnique:
    id: str
    tactic: str
    name: str
    depth: int  # 0 = top-level technique, 1 = Level 0, 2 = Level 1
    parent_id: str | None
    definition: str


def parse_d3fend_csv(text: str) -> list[D3fendTechnique]:
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None or list(reader.fieldnames) != REQUIRED_HEADERS:
        raise D3fendParseError(
            f"unexpected D3FEND CSV header {reader.fieldnames!r}; expected {REQUIRED_HEADERS!r}"
        )

    techniques: list[D3fendTechnique] = []
    parent_at_depth: dict[int, str] = {}

    for row in reader:
        d3fend_id = (row["ID"] or "").strip()
        if not d3fend_id:
            continue

        tactic = (row["D3FEND Tactic"] or "").strip()
        definition = (row["Definition"] or "").strip()

        if (row["D3FEND Technique"] or "").strip():
            depth = 0
            name = row["D3FEND Technique"].strip()
        elif (row["D3FEND Technique Level 0"] or "").strip():
            depth = 1
            name = row["D3FEND Technique Level 0"].strip()
        elif (row["D3FEND Technique Level 1"] or "").strip():
            depth = 2
            name = row["D3FEND Technique Level 1"].strip()
        else:
            raise D3fendParseError(f"row {d3fend_id!r} has no technique name at any level")

        parent_id = parent_at_depth.get(depth - 1) if depth > 0 else None

        for deeper_or_equal in [d for d in parent_at_depth if d >= depth]:
            del parent_at_depth[deeper_or_equal]
        parent_at_depth[depth] = d3fend_id

        techniques.append(
            D3fendTechnique(
                id=d3fend_id,
                tactic=tactic,
                name=name,
                depth=depth,
                parent_id=parent_id,
                definition=definition,
            )
        )

    return techniques
