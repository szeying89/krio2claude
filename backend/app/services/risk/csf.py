"""NIST CSF 2.0 function codes, derived from a CRI `profile_id` (e.g.
`"GV.OC-01.01"` -> `"GV"`) rather than from `DiagnosticStatement.csf_path`
(which holds the CRI workbook's own spelled-out function name, e.g.
`"GOVERN"`, split from free text) — the profile_id prefix is the stable,
structural source for this and needs no text parsing.
"""

from __future__ import annotations

CSF_FUNCTIONS = ("GV", "ID", "PR", "DE", "RS", "RC")


def csf_function_code(profile_id: str) -> str:
    return profile_id.split(".", 1)[0]
