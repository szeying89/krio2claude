"""A JSON Schema for OTM 0.2.0, authored directly against this
platform's own `to_otm` mapping (`app/services/systemmodel/otm.py`) —
not fetched from the published spec (this sandbox has no network access
for schema-hosting sites, the same fixture policy Task 3 established for
MITRE data: representative and locally authored, not vendored from a
live source). It validates the structural shape any generic OTM 0.2.0
consumer needs — `otmVersion`, `project`, `trustZones`, `components`,
`dataflows`, `assets`, `mitigations` — without trying to fully replicate
every optional field the full spec allows.
"""

from __future__ import annotations

from typing import Any

import jsonschema

OTM_SCHEMA: dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "required": ["otmVersion", "project", "trustZones", "components", "dataflows", "assets", "mitigations"],
    "properties": {
        "otmVersion": {"type": "string"},
        "project": {
            "type": "object",
            "required": ["id", "name"],
            "properties": {"id": {"type": "string"}, "name": {"type": "string"}},
        },
        "trustZones": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "name"],
                "properties": {"id": {"type": "string"}, "name": {"type": "string"}},
            },
        },
        "components": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "name", "type"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "type": {"type": "string"},
                },
            },
        },
        "dataflows": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "name", "source", "destination"],
                "properties": {
                    "id": {"type": "string"},
                    "source": {"type": "string"},
                    "destination": {"type": "string"},
                },
            },
        },
        "assets": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "name"],
                "properties": {"id": {"type": "string"}, "name": {"type": "string"}},
            },
        },
        "mitigations": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["id", "name", "riskReduction"],
                "properties": {
                    "id": {"type": "string"},
                    "name": {"type": "string"},
                    "riskReduction": {"type": "number"},
                },
            },
        },
    },
}


def validate_otm(document: dict[str, Any]) -> None:
    """Raises `jsonschema.ValidationError` if `document` doesn't conform —
    should never happen for our own generator, so a failure here is
    treated as a real bug in `to_otm`, not an expected user-facing error."""
    jsonschema.validate(document, OTM_SCHEMA)
