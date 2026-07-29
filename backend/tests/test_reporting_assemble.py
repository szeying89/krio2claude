from datetime import UTC, datetime

from app.models.project import ImpactTiering
from app.services.assurance.rubric import ConfidenceReport, RubricDimension
from app.services.reporting.assemble import assemble_report_data
from app.services.systemmodel.models import SystemModel


def _confidence():
    dim = RubricDimension(name="x", score=80.0, weight=1 / 6, raw_counts={}, detail="")
    return ConfidenceReport(dimensions=(dim,) * 6, overall_score=80.0, band="High")


def _model():
    return SystemModel(id="p1", version=1, parent_version=None)


def test_assemble_with_no_tiering_reports_a_clear_not_yet_computed_message():
    data = assemble_report_data(
        project_name="Demo", business_criticality="high", model=_model(), confidence=_confidence(),
        risk_findings=[], csf_rollup=[], tiering=None, gaps=[], residual_risk=None, roadmap=[],
        recommendations=[], adjudicated_threats=[], rejection_log=[], assumptions=[], currency=None,
        has_cri=False,
    )
    assert data.tier is None
    assert "not been computed" in data.tier_justification


def test_assemble_with_tiering_and_triggering_question_reports_it():
    tiering = ImpactTiering(
        project_id="p1", tier=3, triggering_question_id="Q3.1", answers=[], computed_at=datetime.now(UTC)
    )
    data = assemble_report_data(
        project_name="Demo", business_criticality="high", model=_model(), confidence=_confidence(),
        risk_findings=[], csf_rollup=[], tiering=tiering, gaps=[], residual_risk=None, roadmap=[],
        recommendations=[], adjudicated_threats=[], rejection_log=[], assumptions=[], currency=None,
        has_cri=True,
    )
    assert data.tier == 3
    assert "Q3.1" in data.tier_justification


def test_assemble_with_tiering_fallthrough_and_no_triggering_question():
    tiering = ImpactTiering(
        project_id="p1", tier=4, triggering_question_id=None, answers=[], computed_at=datetime.now(UTC)
    )
    data = assemble_report_data(
        project_name="Demo", business_criticality="high", model=_model(), confidence=_confidence(),
        risk_findings=[], csf_rollup=[], tiering=tiering, gaps=[], residual_risk=None, roadmap=[],
        recommendations=[], adjudicated_threats=[], rejection_log=[], assumptions=[], currency=None,
        has_cri=True,
    )
    assert data.tier == 4
    assert "fallthrough" in data.tier_justification


def test_model_version_and_out_of_scope_properties_delegate_to_model():
    model = _model()
    data = assemble_report_data(
        project_name="Demo", business_criticality="high", model=model, confidence=_confidence(),
        risk_findings=[], csf_rollup=[], tiering=None, gaps=[], residual_risk=None, roadmap=[],
        recommendations=[], adjudicated_threats=[], rejection_log=[], assumptions=[], currency=None,
        has_cri=False,
    )
    assert data.model_version == model.version
    assert data.out_of_scope == tuple(model.out_of_scope)
