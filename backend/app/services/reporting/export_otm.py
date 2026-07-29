"""Task 22's OTM export: reuses Task 9's `to_otm` directly and validates
the result against `otm_schema.py` before ever handing it back — a
schema-validation failure here means `to_otm` itself produced a
malformed document, a real bug to surface loudly rather than silently
export something an external OTM consumer would reject.
"""

from __future__ import annotations

from typing import Any

from app.services.reporting.otm_schema import validate_otm
from app.services.systemmodel.models import SystemModel
from app.services.systemmodel.otm import to_otm


def export_otm(model: SystemModel) -> dict[str, Any]:
    document = to_otm(model)
    validate_otm(document)
    return document
