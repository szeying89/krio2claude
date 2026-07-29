"""Prompt-injection indicator detection (Task 18): a deterministic,
rule-based scanner run over raw article text *before* it is ever sent to
the LLM. Matches are logged as `injection_indicators` and surfaced to the
caller — never acted on, and never able to change what the extraction
prompt asks for (the prompt template itself also delimits the article
text as quoted data, see `extraction.py`'s docstring, so this scanner is
belt-and-suspenders visibility, not the only defense).
"""

from __future__ import annotations

import re

_INJECTION_PATTERNS = [
    re.compile(r"ignore (all |any |the )?(previous|prior|above)\s+instructions?", re.IGNORECASE),
    re.compile(r"disregard (all |any |the )?(previous|prior|above)", re.IGNORECASE),
    re.compile(r"you (must|should|will) now", re.IGNORECASE),
    re.compile(r"new instructions?\s*:", re.IGNORECASE),
    re.compile(r"^\s*system\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"^\s*assistant\s*:", re.IGNORECASE | re.MULTILINE),
    re.compile(r"mark (all )?threats?\s+(as\s+)?resolved", re.IGNORECASE),
    re.compile(r"act as (an?|the)\b", re.IGNORECASE),
    re.compile(r"do not (extract|report|flag)\s+(this|anything)", re.IGNORECASE),
]


def detect_injection_indicators(text: str) -> tuple[str, ...]:
    """Returns the distinct matched snippets, in the order their patterns
    are checked — deterministic and stable across runs on the same text."""
    indicators = []
    for pattern in _INJECTION_PATTERNS:
        match = pattern.search(text)
        if match:
            indicators.append(match.group(0).strip())
    return tuple(indicators)
