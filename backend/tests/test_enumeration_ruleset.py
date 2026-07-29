import pytest

from app.services.enumeration.ruleset import RulesetLoadError, load_ruleset, parse_ruleset

MINIMAL_VALID = """
version: "1.0.0"
element_rules:
  - match_kind: process
    categories: [spoofing]
linddun:
  categories: [linkability]
"""


def test_default_ruleset_loads():
    ruleset = load_ruleset()
    assert ruleset.version == "1.0.0"
    assert len(ruleset.element_rules) > 0
    assert len(ruleset.linddun_categories) == 7


def test_minimal_valid_ruleset_parses():
    ruleset = parse_ruleset(MINIMAL_VALID)
    assert ruleset.version == "1.0.0"
    assert ruleset.element_rules[0].match_kind == "process"
    assert ruleset.linddun_personal_data_classifications == ()


def test_missing_version_fails_fast():
    bad = "element_rules:\n  - match_kind: process\n    categories: [spoofing]\nlinddun:\n  categories: [linkability]\n"
    with pytest.raises(RulesetLoadError, match="version"):
        parse_ruleset(bad)


def test_empty_element_rules_fails_fast():
    bad = 'version: "1.0.0"\nelement_rules: []\nlinddun:\n  categories: [linkability]\n'
    with pytest.raises(RulesetLoadError, match="element_rules"):
        parse_ruleset(bad)


def test_unknown_match_kind_fails_fast():
    bad = (
        'version: "1.0.0"\nelement_rules:\n  - match_kind: spaceship\n    categories: [spoofing]\n'
        "linddun:\n  categories: [linkability]\n"
    )
    with pytest.raises(RulesetLoadError, match="spaceship"):
        parse_ruleset(bad)


def test_unknown_stride_category_fails_fast():
    bad = (
        'version: "1.0.0"\nelement_rules:\n  - match_kind: process\n    categories: [not_a_real_category]\n'
        "linddun:\n  categories: [linkability]\n"
    )
    with pytest.raises(RulesetLoadError, match="not_a_real_category"):
        parse_ruleset(bad)


def test_unknown_linddun_category_fails_fast():
    bad = (
        'version: "1.0.0"\nelement_rules:\n  - match_kind: process\n    categories: [spoofing]\n'
        "linddun:\n  categories: [not_a_real_category]\n"
    )
    with pytest.raises(RulesetLoadError, match="not_a_real_category"):
        parse_ruleset(bad)


def test_missing_linddun_section_fails_fast():
    bad = 'version: "1.0.0"\nelement_rules:\n  - match_kind: process\n    categories: [spoofing]\n'
    with pytest.raises(RulesetLoadError, match="linddun"):
        parse_ruleset(bad)


def test_missing_categories_on_rule_fails_fast():
    bad = 'version: "1.0.0"\nelement_rules:\n  - match_kind: process\nlinddun:\n  categories: [linkability]\n'
    with pytest.raises(RulesetLoadError, match="categories"):
        parse_ruleset(bad)


def test_invalid_yaml_fails_fast():
    with pytest.raises(RulesetLoadError, match="YAML"):
        parse_ruleset("not: valid: yaml: [")


def test_non_mapping_top_level_fails_fast():
    with pytest.raises(RulesetLoadError):
        parse_ruleset("- just\n- a\n- list\n")


def test_load_ruleset_missing_file_fails_fast(tmp_path):
    with pytest.raises(RulesetLoadError, match="could not read"):
        load_ruleset(tmp_path / "does-not-exist.yaml")
