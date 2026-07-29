"""Task 22's canonical JSON export — a straight, deterministic
serialization of `ReportData` (every field is already a plain dataclass
of primitives/tuples/nested dataclasses, so `dataclasses.asdict` handles
it without any bespoke `to_dict` per artifact type)."""

from __future__ import annotations

import dataclasses
import json
from typing import Any

from app.services.reporting.models import ReportData


def report_data_to_dict(data: ReportData) -> dict[str, Any]:
    return dataclasses.asdict(data)


def export_json(data: ReportData) -> str:
    return json.dumps(report_data_to_dict(data), indent=2, sort_keys=True, default=str)
