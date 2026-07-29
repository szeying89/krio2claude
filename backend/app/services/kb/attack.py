"""ATT&CK Enterprise STIX 2.1 bundle parser.

Verified against the real attack-stix-data feed: each domain is published as
its own bundle (enterprise-attack-<version>.json) where every attack-pattern
object's x_mitre_domains is exactly ["enterprise-attack"] — ICS and Mobile
each get their own separate file. A domain outside {"enterprise-attack"}
showing up here means the wrong file was fetched (or a test fixture is
deliberately exercising the failure path), so it is rejected outright rather
than filtered out silently.
"""

from __future__ import annotations

from app.services.kb.models import TechniqueChunk, UnsupportedDomainError

ENTERPRISE_DOMAIN = "enterprise-attack"
ENTERPRISE_KILL_CHAIN = "mitre-attack"
ENTERPRISE_ID_SOURCE = "mitre-attack"


def _external_id(obj: dict, source_name: str) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == source_name and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def parse_attack_enterprise_bundle(bundle: dict) -> list[TechniqueChunk]:
    chunks: list[TechniqueChunk] = []

    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue

        domains = set(obj.get("x_mitre_domains", []))
        disallowed = domains - {ENTERPRISE_DOMAIN}
        if disallowed:
            raise UnsupportedDomainError(
                f"object {obj.get('id')} declares unsupported domain(s) "
                f"{sorted(disallowed)}; only {ENTERPRISE_DOMAIN!r} is permitted "
                "in the Enterprise KB (no ICS, no Mobile)"
            )
        if ENTERPRISE_DOMAIN not in domains:
            continue

        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue

        technique_id = _external_id(obj, ENTERPRISE_ID_SOURCE)
        if technique_id is None:
            continue

        tactics = tuple(
            phase["phase_name"]
            for phase in obj.get("kill_chain_phases", [])
            if phase.get("kill_chain_name") == ENTERPRISE_KILL_CHAIN
        )

        chunks.append(
            TechniqueChunk(
                id=technique_id,
                matrix="enterprise",
                name=obj.get("name", ""),
                tactics=tactics,
                description=obj.get("description", ""),
                detection=obj.get("x_mitre_detection", "") or "",
                platforms=tuple(obj.get("x_mitre_platforms") or ()),
                data_sources=tuple(obj.get("x_mitre_data_sources") or ()),
            )
        )

    return chunks
