"""CAPEC -> ATT&CK bridge parser.

Verified against the real feed at mitre/cti (capec/2.1/stix-capec.json):
CAPEC is published as STIX too, and each attack-pattern object carries its
own CAPEC ID (external_references source_name "capec") alongside zero or
more ATT&CK technique mappings (source_name "ATTACK") in the same
external_references list — no separate relationship objects needed.
"""

from __future__ import annotations

from collections import defaultdict

CAPEC_ID_SOURCE = "capec"
ATTACK_MAPPING_SOURCE = "ATTACK"


def parse_capec_bundle(bundle: dict) -> dict[str, list[str]]:
    """Return {attack_technique_id: [capec_id, ...]}."""
    mapping: dict[str, list[str]] = defaultdict(list)

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        refs = obj.get("external_references", [])
        capec_id = next(
            (
                f"CAPEC-{ref['external_id'].removeprefix('CAPEC-')}"
                for ref in refs
                if ref.get("source_name") == CAPEC_ID_SOURCE and ref.get("external_id")
            ),
            None,
        )
        if capec_id is None:
            continue

        for ref in refs:
            if ref.get("source_name") == ATTACK_MAPPING_SOURCE and ref.get("external_id"):
                mapping[ref["external_id"]].append(capec_id)

    return dict(mapping)
