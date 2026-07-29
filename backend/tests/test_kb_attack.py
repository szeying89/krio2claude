import pytest

from app.services.kb.attack import parse_attack_enterprise_bundle
from app.services.kb.models import UnsupportedDomainError
from tests.kb_fixtures import load_json


def test_parses_active_enterprise_techniques_only():
    bundle = load_json("enterprise_bundle.json")
    chunks = parse_attack_enterprise_bundle(bundle)

    ids = {c.id for c in chunks}
    assert ids == {"T1190", "T1071", "T1055.011"}, "revoked/deprecated/non-technique excluded"


def test_normalises_fields_from_stix_shape():
    bundle = load_json("enterprise_bundle.json")
    chunks = {c.id: c for c in parse_attack_enterprise_bundle(bundle)}

    t1190 = chunks["T1190"]
    assert t1190.matrix == "enterprise"
    assert t1190.name == "Exploit Public-Facing Application"
    assert t1190.tactics == ("initial-access",)
    assert "Monitor application logs" in t1190.detection
    assert set(t1190.platforms) == {"Linux", "Windows", "macOS"}
    assert t1190.data_sources == ("Application Log: Application Log Content",)


def test_null_optional_fields_normalise_to_empty():
    bundle = load_json("enterprise_bundle.json")
    chunks = {c.id: c for c in parse_attack_enterprise_bundle(bundle)}

    sub = chunks["T1055.011"]
    assert sub.detection == ""
    assert sub.data_sources == ()
    assert sub.tactics == ("defense-evasion", "privilege-escalation")


def test_ics_tagged_object_rejects_the_whole_load():
    bundle = load_json("enterprise_bundle_with_ics.json")
    with pytest.raises(UnsupportedDomainError, match="ics-attack"):
        parse_attack_enterprise_bundle(bundle)
