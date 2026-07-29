from app.services.systemmodel.models import Component
from app.services.systemmodel.out_of_scope import detect_out_of_scope


def _component(id_: str, name: str, tags: tuple[str, ...] = ()) -> Component:
    return Component(id=id_, name=name, kind="process", trust_zone_id="tz1", technology_tags=tags)


def test_scada_indicator_flags_component():
    components = [_component("c1", "SCADA Historian Gateway")]
    declarations = detect_out_of_scope(components)
    assert len(declarations) == 1
    assert declarations[0].category == "ot_ics"
    assert components[0].out_of_scope is True


def test_plc_indicator_via_technology_tag():
    components = [_component("c1", "Field Controller", tags=("PLC", "Modbus"))]
    declarations = detect_out_of_scope(components)
    assert declarations[0].category == "ot_ics"


def test_mobile_indicator_flags_component():
    components = [_component("c1", "Customer Mobile App")]
    declarations = detect_out_of_scope(components)
    assert declarations[0].category == "mobile_client"


def test_android_indicator():
    components = [_component("c1", "Android Client")]
    declarations = detect_out_of_scope(components)
    assert declarations[0].category == "mobile_client"


def test_no_false_positive_for_rtu_substring_in_ordinary_word():
    components = [_component("c1", "Virtual Machine Gateway")]
    declarations = detect_out_of_scope(components)
    assert declarations == []
    assert components[0].out_of_scope is False


def test_no_false_positive_for_ios_substring_in_ordinary_word():
    components = [_component("c1", "Studios Backend Service")]
    declarations = detect_out_of_scope(components)
    assert declarations == []


def test_clean_it_component_is_untouched():
    components = [_component("c1", "Payment Gateway")]
    declarations = detect_out_of_scope(components)
    assert declarations == []
    assert components[0].out_of_scope is False
    assert components[0].out_of_scope_reason is None


def test_ot_takes_precedence_over_mobile_when_both_present():
    components = [_component("c1", "Mobile SCADA Client")]
    declarations = detect_out_of_scope(components)
    assert len(declarations) == 1
    assert declarations[0].category == "ot_ics"


def test_component_stays_in_the_list_marked_out_of_scope_not_removed():
    components = [_component("c1", "SCADA Historian")]
    detect_out_of_scope(components)
    assert len(components) == 1
    assert components[0].id == "c1"
