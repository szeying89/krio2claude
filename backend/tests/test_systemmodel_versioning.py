from app.services.systemmodel.models import Component, SystemModel
from app.services.systemmodel.versioning import diff_models


def _model(version: int, components: list[Component]) -> SystemModel:
    return SystemModel(id="proj1", version=version, parent_version=None, components=components)


def test_diff_against_none_reports_initial_version():
    model = _model(1, [Component(id="c1", name="A", kind="process", trust_zone_id="tz1")])
    summary = diff_models(None, model)
    assert len(summary) == 1
    assert "initial version" in summary[0]


def test_diff_detects_added_component():
    before = _model(1, [])
    after = _model(2, [Component(id="c1", name="Auth Service", kind="process", trust_zone_id="tz1")])
    summary = diff_models(before, after)
    assert any("added component 'Auth Service'" in line for line in summary)


def test_diff_detects_removed_component():
    before = _model(1, [Component(id="c1", name="Auth Service", kind="process", trust_zone_id="tz1")])
    after = _model(2, [])
    summary = diff_models(before, after)
    assert any("removed component 'Auth Service'" in line for line in summary)


def test_diff_detects_changed_component():
    before = _model(1, [Component(id="c1", name="Auth Service", kind="process", trust_zone_id="tz1")])
    after = _model(2, [Component(id="c1", name="Auth Service", kind="datastore", trust_zone_id="tz1")])
    summary = diff_models(before, after)
    assert any("changed component 'Auth Service'" in line for line in summary)


def test_diff_reports_no_changes_when_identical():
    before = _model(1, [Component(id="c1", name="Auth Service", kind="process", trust_zone_id="tz1")])
    after = _model(2, [Component(id="c1", name="Auth Service", kind="process", trust_zone_id="tz1")])
    summary = diff_models(before, after)
    assert summary == ["no structural changes from the previous version"]


def test_diff_ignores_unrelated_unchanged_elements():
    before = _model(
        1,
        [
            Component(id="c1", name="Auth Service", kind="process", trust_zone_id="tz1"),
            Component(id="c2", name="User DB", kind="datastore", trust_zone_id="tz1"),
        ],
    )
    after = _model(
        2,
        [
            Component(id="c1", name="Auth Service", kind="process", trust_zone_id="tz1"),
            Component(id="c2", name="User DB", kind="datastore", trust_zone_id="tz1", technology_tags=("Postgres",)),
        ],
    )
    summary = diff_models(before, after)
    assert len(summary) == 1
    assert "User DB" in summary[0]
