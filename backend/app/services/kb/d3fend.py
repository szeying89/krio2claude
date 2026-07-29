"""D3FEND -> ATT&CK bridge parser.

d3fend.mitre.org is not reachable from this environment to verify its exact
export shape, so this parses D3FEND's published offense-to-defense mapping
as a flattened list of rows — the shape its "full mappings" export takes
regardless of the precise upstream API used to fetch it:
[{"attack_id": "T1071", "d3fend_id": "D3-NTA", "d3fend_name": "Network
Traffic Analysis"}, ...]. If the real export differs, only the fetcher
(app/services/kb/fetchers.py) needs to change to reshape it into this form.
"""

from __future__ import annotations

from collections import defaultdict


def parse_d3fend_mappings(rows: list[dict]) -> dict[str, list[str]]:
    """Return {attack_technique_id: [d3fend_id, ...]}."""
    mapping: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        attack_id = row.get("attack_id")
        d3fend_id = row.get("d3fend_id")
        if attack_id and d3fend_id:
            mapping[attack_id].append(d3fend_id)
    return dict(mapping)
