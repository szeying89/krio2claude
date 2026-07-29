from app.services.cri.models import DiagnosticStatement
from app.services.kb.d3fend import D3fendTechnique
from app.services.mitigation.inventory import build_control_inventory
from app.services.systemmodel.models import DeclaredControl


def _d3fend(id_="D3-MFA", name="Multi-factor Authentication", definition="Requiring multiple authentication factors for login."):
    return D3fendTechnique(id=id_, tactic="Harden", name=name, depth=0, parent_id=None, definition=definition)


def _statement(profile_id="PR.AA-03.01", name="Authentication", text="Multi-factor authentication is required for privileged users.", tiers=(1, 2, 3, 4)):
    return DiagnosticStatement(outline_id="1", profile_id=profile_id, csf_path=("PROTECT",), name=name, text=text, applicable_tiers=tiers)


def test_control_matches_relevant_d3fend_countermeasure():
    controls = [DeclaredControl(id="c1", name="Multi-Factor Authentication", applies_to_ids=("gw",))]
    entries = build_control_inventory(controls, [_d3fend()], [])
    assert entries[0].d3fend_ids == ("D3-MFA",)


def test_control_matches_relevant_cri_statement():
    controls = [DeclaredControl(id="c1", name="Multi-Factor Authentication", applies_to_ids=("gw",))]
    entries = build_control_inventory(controls, [], [_statement()])
    assert entries[0].cri_statement_ids == ("PR.AA-03.01",)


def test_control_does_not_match_unrelated_d3fend_or_cri():
    controls = [DeclaredControl(id="c1", name="Multi-Factor Authentication", applies_to_ids=("gw",))]
    unrelated_d3fend = _d3fend(id_="D3-ENC", name="Message Encryption", definition="Encrypting messages in transit.")
    unrelated_statement = _statement(profile_id="PR.DS-01.01", name="Encryption", text="Data at rest is encrypted using strong algorithms.")
    entries = build_control_inventory(controls, [unrelated_d3fend], [unrelated_statement])
    assert entries[0].d3fend_ids == ()
    assert entries[0].cri_statement_ids == ()


def test_every_declared_control_produces_an_inventory_entry():
    controls = [
        DeclaredControl(id="c1", name="Multi-Factor Authentication", applies_to_ids=()),
        DeclaredControl(id="c2", name="Something Unrelated Entirely", applies_to_ids=()),
    ]
    entries = build_control_inventory(controls, [_d3fend()], [_statement()])
    assert {e.control_id for e in entries} == {"c1", "c2"}
    unrelated = next(e for e in entries if e.control_id == "c2")
    assert unrelated.d3fend_ids == ()
    assert unrelated.cri_statement_ids == ()


def test_control_can_match_multiple_targets():
    controls = [DeclaredControl(id="c1", name="Authentication Hardening", applies_to_ids=())]
    d3fend = [
        _d3fend(id_="D3-MFA", name="Multi-factor Authentication", definition="Authentication hardening via multiple factors."),
        _d3fend(id_="D3-CRED", name="Credential Hardening", definition="Authentication hardening via credential policy."),
    ]
    entries = build_control_inventory(controls, d3fend, [])
    assert set(entries[0].d3fend_ids) == {"D3-MFA", "D3-CRED"}


def test_empty_declared_controls_produces_empty_inventory():
    assert build_control_inventory([], [_d3fend()], [_statement()]) == []
