"""Real network fetchers for the four KB sources.

Deliberately isolated from parsing (app/services/kb/{attack,atlas,capec,
d3fend}.py) so tests exercise normalization against committed fixtures with
no network calls at all — these functions are only wired in as the
KBRefreshService's default fetchers, never invoked directly by tests.

URLs verified reachable from this environment except D3FEND's own domain
(d3fend.mitre.org), which this sandbox's network policy blocks; see the
caveat in d3fend.py.

No ICS or Mobile fetchers exist here, deliberately (Requirement 11):
fetch_attack_enterprise resolves the enterprise-attack collection from
index.json by URL shape and never constructs an ICS or Mobile URL.
"""

from __future__ import annotations

from typing import Any

import httpx
import yaml

ENTERPRISE_INDEX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/index.json"
)
ATLAS_YAML_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
CAPEC_STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json"
# Best-effort default; d3fend.mitre.org is unreachable from this sandbox to
# verify the exact download path. The CSV shape itself (ID, D3FEND Tactic,
# D3FEND Technique, Level 0, Level 1, Definition) is confirmed real — a user
# supplied a live export in this shape — so d3fend.py's parser is verified
# even though this URL isn't.
D3FEND_CSV_URL = "https://d3fend.mitre.org/resources/D3FEND.csv"

_TIMEOUT = 60.0


class KBFetchError(Exception):
    pass


def _get_json(client: httpx.Client, url: str) -> Any:
    response = client.get(url, timeout=_TIMEOUT)
    response.raise_for_status()
    return response.json()


def fetch_attack_enterprise(client: httpx.Client | None = None) -> tuple[dict, str, str]:
    owns_client = client is None
    client = client or httpx.Client()
    try:
        index = _get_json(client, ENTERPRISE_INDEX_URL)
        for collection in index.get("collections", []):
            versions = collection.get("versions", [])
            if not versions:
                continue
            latest = versions[0]
            url = latest.get("url", "")
            if "/enterprise-attack/enterprise-attack-" in url:
                bundle = _get_json(client, url)
                return bundle, str(latest["version"]), url
        raise KBFetchError("no enterprise-attack collection found in index.json")
    finally:
        if owns_client:
            client.close()


def fetch_atlas(client: httpx.Client | None = None) -> tuple[dict, str, str]:
    owns_client = client is None
    client = client or httpx.Client()
    try:
        response = client.get(ATLAS_YAML_URL, timeout=_TIMEOUT)
        response.raise_for_status()
        data = yaml.safe_load(response.text)
        return data, str(data.get("version", "unknown")), ATLAS_YAML_URL
    finally:
        if owns_client:
            client.close()


def fetch_capec(client: httpx.Client | None = None) -> tuple[dict, str, str]:
    owns_client = client is None
    client = client or httpx.Client()
    try:
        bundle = _get_json(client, CAPEC_STIX_URL)
        version = "unknown"
        for obj in bundle.get("objects", []):
            if obj.get("type") == "attack-pattern" and obj.get("x_capec_version"):
                version = str(obj["x_capec_version"])
                break
        return bundle, version, CAPEC_STIX_URL
    finally:
        if owns_client:
            client.close()


def fetch_d3fend(client: httpx.Client | None = None) -> tuple[str, str, str]:
    owns_client = client is None
    client = client or httpx.Client()
    try:
        response = client.get(D3FEND_CSV_URL, timeout=_TIMEOUT)
        response.raise_for_status()
        return response.text, "unknown", D3FEND_CSV_URL
    finally:
        if owns_client:
            client.close()
