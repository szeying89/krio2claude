"""Shared lexical-overlap heuristic matcher.

Used where the plan calls for a technique bridge (D3FEND->ATT&CK in Task 3,
CRI diagnostic-statement->ATT&CK in Task 4) but no authoritative mapping
source is available. This is deliberately simple, deterministic, and
rule-based — no LLM, no network — matching the reproducibility guarantees
the rest of the KB pipeline depends on.

Every result is a *heuristic* candidate, never an authoritative mapping: it
carries the matched keywords as its rationale so it can be displayed,
audited, and never silently confused with a real, sourced mapping (the
plan's cri_mapping_absent / mapping_inferred distinction — this module only
ever produces mapping_inferred results).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.kb.models import TechniqueChunk

_WORD_RE = re.compile(r"[a-z0-9]+")

_STOPWORDS = {
    "the", "and", "for", "with", "that", "this", "from", "into", "over",
    "your", "their", "such", "these", "those", "will", "shall", "should",
    "organization", "organizational", "institution", "institutions",
    "management", "process", "processes", "system", "systems", "security",
    "policy", "policies", "program", "programs", "documentation", "document",
    "documents", "control", "controls", "requirement", "requirements",
    "activity", "activities", "using", "used", "based", "related", "level",
    "technology", "cybersecurity", "risk", "data", "information",
}

_MIN_TOKEN_LEN = 3  # short enough to keep common security acronyms (DNS, SQL, TLS, ARP, ...)


@dataclass(frozen=True)
class HeuristicSource:
    """A generic (id, name, text) tuple to match against ATT&CK/ATLAS
    techniques — works for a D3FEND technique or a CRI diagnostic
    statement without either module depending on the other's model."""

    id: str
    name: str
    text: str


@dataclass(frozen=True)
class InferredMapping:
    technique_id: str
    matched_terms: tuple[str, ...]


def tokenize(text: str) -> set[str]:
    tokens = {w for w in _WORD_RE.findall(text.lower()) if len(w) >= _MIN_TOKEN_LEN}
    return tokens - _STOPWORDS


def infer_technique_mappings(
    sources: list[HeuristicSource],
    techniques: list[TechniqueChunk],
    min_shared_tokens: int = 2,
) -> dict[str, list[InferredMapping]]:
    """Return {source_id: [InferredMapping, ...]}, deterministic and ordered
    by technique_id for reproducibility."""
    # Match against technique *names* only (not full descriptions) — names
    # are short and specific, so a 2+ token overlap is a meaningful signal;
    # matching against full descriptions would drown in noise.
    technique_tokens = [(t, tokenize(t.name)) for t in techniques]

    results: dict[str, list[InferredMapping]] = {}
    for source in sources:
        source_tokens = tokenize(f"{source.name} {source.text}")
        if not source_tokens:
            continue
        matches: list[InferredMapping] = []
        for technique, tokens in technique_tokens:
            shared = tuple(sorted(source_tokens & tokens))
            if len(shared) >= min_shared_tokens:
                matches.append(InferredMapping(technique_id=technique.id, matched_terms=shared))
        if matches:
            matches.sort(key=lambda m: m.technique_id)
            results[source.id] = matches

    return results
