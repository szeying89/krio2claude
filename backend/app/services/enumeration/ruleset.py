"""Versioned STRIDE/LINDDUN ruleset loading (Task 10).

A ruleset is data, not code — a versioned YAML file mapping DFD element
kinds (and, optionally, a required technology tag) to the STRIDE
categories they contribute, plus a LINDDUN trigger on personal-data
classifications/tags. Malformed rulesets fail fast at load, with an
actionable message naming exactly what's wrong — never a partially-loaded
ruleset silently missing rules.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

_VALID_KINDS = {"external_entity", "process", "datastore", "dataflow"}


class STRIDECategory(str, enum.Enum):
    SPOOFING = "spoofing"
    TAMPERING = "tampering"
    REPUDIATION = "repudiation"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    ELEVATION_OF_PRIVILEGE = "elevation_of_privilege"


class LINDDUNCategory(str, enum.Enum):
    LINKABILITY = "linkability"
    IDENTIFIABILITY = "identifiability"
    NON_REPUDIATION = "non_repudiation"
    DETECTABILITY = "detectability"
    DISCLOSURE_OF_INFORMATION = "disclosure_of_information"
    UNAWARENESS = "unawareness"
    NON_COMPLIANCE = "non_compliance"


class RulesetLoadError(Exception):
    pass


@dataclass(frozen=True)
class ElementRule:
    match_kind: str
    categories: tuple[STRIDECategory, ...]
    match_tag: str | None = None


@dataclass(frozen=True)
class Ruleset:
    version: str
    element_rules: tuple[ElementRule, ...]
    linddun_categories: tuple[LINDDUNCategory, ...]
    linddun_personal_data_classifications: tuple[str, ...]
    linddun_personal_data_tags: tuple[str, ...]


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise RulesetLoadError(message)


def _parse_stride_category(raw: Any, context: str) -> STRIDECategory:
    _require(isinstance(raw, str), f"{context}: category must be a string, got {raw!r}")
    try:
        return STRIDECategory(raw)
    except ValueError as exc:
        valid = ", ".join(c.value for c in STRIDECategory)
        raise RulesetLoadError(
            f"{context}: unknown STRIDE category {raw!r}; valid categories are: {valid}"
        ) from exc


def _parse_linddun_category(raw: Any, context: str) -> LINDDUNCategory:
    _require(isinstance(raw, str), f"{context}: category must be a string, got {raw!r}")
    try:
        return LINDDUNCategory(raw)
    except ValueError as exc:
        valid = ", ".join(c.value for c in LINDDUNCategory)
        raise RulesetLoadError(
            f"{context}: unknown LINDDUN category {raw!r}; valid categories are: {valid}"
        ) from exc


def _parse_element_rule(raw: Any, index: int) -> ElementRule:
    context = f"element_rules[{index}]"
    _require(isinstance(raw, dict), f"{context}: expected a mapping, got {raw!r}")

    match_kind = raw.get("match_kind")
    _require(isinstance(match_kind, str), f"{context}: missing or non-string 'match_kind'")
    _require(
        match_kind in _VALID_KINDS,
        f"{context}: unknown match_kind {match_kind!r}; valid kinds are: "
        f"{', '.join(sorted(_VALID_KINDS))}",
    )

    match_tag = raw.get("match_tag")
    _require(
        match_tag is None or isinstance(match_tag, str),
        f"{context}: 'match_tag' must be a string if present",
    )

    categories_raw = raw.get("categories")
    _require(
        isinstance(categories_raw, list) and len(categories_raw) > 0,
        f"{context}: 'categories' must be a non-empty list",
    )
    categories = tuple(
        _parse_stride_category(c, f"{context}.categories[{i}]")
        for i, c in enumerate(categories_raw)
    )

    return ElementRule(match_kind=match_kind, match_tag=match_tag, categories=categories)


def parse_ruleset(raw_yaml: str) -> Ruleset:
    try:
        data = yaml.safe_load(raw_yaml)
    except yaml.YAMLError as exc:
        raise RulesetLoadError(f"invalid YAML: {exc}") from exc

    _require(isinstance(data, dict), "ruleset document must be a mapping at the top level")

    version = data.get("version")
    _require(
        isinstance(version, str) and version.strip() != "",
        "missing or empty 'version' field",
    )

    element_rules_raw = data.get("element_rules")
    _require(
        isinstance(element_rules_raw, list) and len(element_rules_raw) > 0,
        "'element_rules' must be a non-empty list",
    )
    element_rules = tuple(
        _parse_element_rule(rule, i) for i, rule in enumerate(element_rules_raw)
    )

    linddun_raw = data.get("linddun")
    _require(isinstance(linddun_raw, dict), "'linddun' section is required and must be a mapping")

    linddun_categories_raw = linddun_raw.get("categories")
    _require(
        isinstance(linddun_categories_raw, list) and len(linddun_categories_raw) > 0,
        "'linddun.categories' must be a non-empty list",
    )
    linddun_categories = tuple(
        _parse_linddun_category(c, f"linddun.categories[{i}]")
        for i, c in enumerate(linddun_categories_raw)
    )

    personal_data_classifications = tuple(linddun_raw.get("personal_data_classifications") or [])
    personal_data_tags = tuple(linddun_raw.get("personal_data_tags") or [])
    _require(
        all(isinstance(c, str) for c in personal_data_classifications),
        "'linddun.personal_data_classifications' must be a list of strings",
    )
    _require(
        all(isinstance(t, str) for t in personal_data_tags),
        "'linddun.personal_data_tags' must be a list of strings",
    )

    return Ruleset(
        version=version,
        element_rules=element_rules,
        linddun_categories=linddun_categories,
        linddun_personal_data_classifications=personal_data_classifications,
        linddun_personal_data_tags=personal_data_tags,
    )


DEFAULT_RULESET_PATH = Path(__file__).parent / "rulesets" / "stride_linddun_v1.yaml"


def load_ruleset(path: Path = DEFAULT_RULESET_PATH) -> Ruleset:
    try:
        raw_yaml = path.read_text()
    except OSError as exc:
        raise RulesetLoadError(f"could not read ruleset file {path}: {exc}") from exc
    return parse_ruleset(raw_yaml)
