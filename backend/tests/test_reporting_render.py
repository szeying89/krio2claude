from app.services.assurance.rubric import ConfidenceReport, RubricDimension
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.reporting.models import ReportData
from app.services.reporting.render import (
    render_ciso_markdown,
    render_executive_markdown,
    render_technical_markdown,
)
from app.services.risk.models import CSFFunctionRollup, RiskFactors, RiskFinding
from app.services.systemmodel.models import Component, OutOfScopeDeclaration, SystemModel, TrustZone


def _confidence():
    dim = RubricDimension(name="x", score=72.0, weight=1 / 6, raw_counts={}, detail="")
    return ConfidenceReport(dimensions=(dim,) * 6, overall_score=72.0, band="Moderate")


def _finding():
    return RiskFinding(
        path_id="path-1", entry_point="client", target="db", technique_ids=("T1190",),
        tactic_sequence=("initial-access",), score=0.5,
        factors=RiskFactors(likelihood=0.5, impact_weight=0.75, statement_density=0.0, d3fend_gap_count=0, cri_gap_count=0, cri_mapping_absent=False),
        csf_functions=("PR",), regulatory_exposure=(),
    )


def _gap():
    return TechniqueGapAnalysis(
        technique_id="T1190", d3fend_required_ids=(), d3fend_observed_ids=(), d3fend_gap_ids=(),
        cri_mapping_absent=False, cri_in_tier_statement_ids=("PR.AA-05.01",), cri_gap_statement_ids=("PR.AA-05.01",),
        cri_mapping_inferred_fallback_ids=(),
    )


def _model(out_of_scope=()):
    return SystemModel(
        id="p1", version=1, parent_version=None,
        trust_zones=[TrustZone(id="tz1", name="Zone", trust_rating=1)],
        components=[Component(id="client", name="Client", kind="external_entity", trust_zone_id="tz1"),
                    Component(id="db", name="DB", kind="datastore", trust_zone_id="tz1")],
        out_of_scope=list(out_of_scope),
    )


def _report_data(has_cri=True, out_of_scope=()):
    return ReportData(
        project_name="Demo", business_criticality="high", model=_model(out_of_scope), confidence=_confidence(),
        risk_findings=(_finding(),), csf_rollup=(CSFFunctionRollup("PR", 1, 1, 1, 1.0),),
        tier=3, tier_justification="Tier 3, determined by question Q3.1.", gaps=(_gap(),),
        residual_risk=None, roadmap=(), recommendations=(), adjudicated_threats=(), rejection_log=(),
        assumptions=(), currency=None, has_cri=has_cri,
    )


def test_shared_confidence_number_agrees_across_all_three_audiences():
    data = _report_data()
    exec_md = render_executive_markdown(data, "exec narrative")
    ciso_md = render_ciso_markdown(data, "ciso narrative")
    tech_md = render_technical_markdown(data, "tech narrative")

    confidence_line = "**Confidence:** 72/100 (Moderate)"
    assert confidence_line in exec_md
    assert confidence_line in ciso_md
    assert confidence_line in tech_md


def test_shared_top_risk_score_agrees_between_executive_and_ciso():
    data = _report_data()
    exec_md = render_executive_markdown(data, "n")
    ciso_md = render_ciso_markdown(data, "n")
    assert "path-1" in exec_md and "0.500" in exec_md
    assert "path-1" in ciso_md and "0.500" in ciso_md


def test_degraded_no_cri_mode_omits_cri_sections_from_ciso_report():
    data = _report_data(has_cri=False)
    ciso_md = render_ciso_markdown(data, "n")
    assert "CRI Diagnostic Statement Gaps" not in ciso_md
    assert "Regulatory Exposure" not in ciso_md


def test_cri_sections_present_when_has_cri_is_true():
    data = _report_data(has_cri=True)
    ciso_md = render_ciso_markdown(data, "n")
    assert "CRI Diagnostic Statement Gaps" in ciso_md


def test_executive_report_includes_narrative_and_limitations():
    data = _report_data(out_of_scope=[OutOfScopeDeclaration(id="d1", subject_id="db", category="ot_ics", indicator="plc", reason="real reason")])
    exec_md = render_executive_markdown(data, "This is the executive narrative.")
    assert "This is the executive narrative." in exec_md
    assert "## Limitations" in exec_md
    assert "real reason" in exec_md


def test_technical_report_includes_dfd_and_appendices():
    tech_md = render_technical_markdown(_report_data(), "tech narrative")
    assert "## System Model (DFD)" in tech_md
    assert "`client`" in tech_md
    assert "## Appendix: Assumptions" in tech_md
    assert "## Appendix: Rejected Candidates" in tech_md
    assert "## Appendix: Not-Applicable Rationales" in tech_md


def test_ciso_report_includes_csf_heatmap_and_tier_justification():
    ciso_md = render_ciso_markdown(_report_data(), "n")
    assert "CSF 2.0 Function Heatmap" in ciso_md
    assert "Tier 3, determined by question Q3.1." in ciso_md
