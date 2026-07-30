"""Out-of-scope detector (Task 9): a deterministic tool, zero LLM calls.

Per IMPLEMENTATION_PLAN.md: OT/ICS indicators (PLC, RTU, SCADA, historian,
Modbus/DNP3/OPC-UA) and mobile-client indicators produce
`OutOfScopeDeclaration` records. The flagged entity stays in the model for
context — it is not deleted — but is marked `out_of_scope=True` so a later
enumeration stage (Task 10+) can exclude it while an out-of-scope panel
still names it in the limitations statement.

Matching is whole-word, not bare substring: a naive substring check on
"rtu" would false-positive on ordinary words like "virtual", and "ios" on
"Studios". Still a documented heuristic, not authoritative — same
"visible, never presented as ground truth" spirit as the KB's
lexical-overlap matcher — it will miss an OT system described in unusual
terms, and that is an accepted, documented limitation.
"""

from __future__ import annotations

import re

from app.services.systemmodel.models import Component, OutOfScopeDeclaration

_OT_ICS_INDICATORS = ("plc", "rtu", "scada", "historian", "modbus", "dnp3", "opc-ua", "opc ua")
_MOBILE_INDICATORS = ("mobile app", "mobile client", "ios app", "android app", "ios", "android")


def _pattern_for(indicator: str) -> re.Pattern[str]:
    return re.compile(r"\b" + re.escape(indicator) + r"\b", re.IGNORECASE)


_OT_ICS_PATTERNS = [(indicator, _pattern_for(indicator)) for indicator in _OT_ICS_INDICATORS]
_MOBILE_PATTERNS = [(indicator, _pattern_for(indicator)) for indicator in _MOBILE_INDICATORS]


def _matched_indicator(haystack: str, patterns: list[tuple[str, re.Pattern[str]]]) -> str | None:
    for indicator, pattern in patterns:
        if pattern.search(haystack):
            return indicator
    return None


def detect_out_of_scope(components: list[Component]) -> list[OutOfScopeDeclaration]:
    declarations: list[OutOfScopeDeclaration] = []
    for component in components:
        haystack = " ".join((component.name, *component.technology_tags))

        ot_match = _matched_indicator(haystack, _OT_ICS_PATTERNS)
        if ot_match is not None:
            component.out_of_scope = True
            component.out_of_scope_reason = f"OT/ICS indicator detected: {ot_match!r}"
            declarations.append(
                OutOfScopeDeclaration(
                    id=f"oos-{component.id}",
                    subject_id=component.id,
                    category="ot_ics",
                    indicator=ot_match,
                    reason=f"{component.name!r} matches OT/ICS indicator {ot_match!r}; "
                    "OT modelling is not supported in this version",
                )
            )
            continue

        mobile_match = _matched_indicator(haystack, _MOBILE_PATTERNS)
        if mobile_match is not None:
            component.out_of_scope = True
            component.out_of_scope_reason = f"mobile-client indicator detected: {mobile_match!r}"
            declarations.append(
                OutOfScopeDeclaration(
                    id=f"oos-{component.id}",
                    subject_id=component.id,
                    category="mobile_client",
                    indicator=mobile_match,
                    reason=f"{component.name!r} matches mobile-client indicator {mobile_match!r}; "
                    "mobile-client modelling is not supported in this version",
                )
            )

    return declarations
