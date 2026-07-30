import io

import jsonschema
import pytest
from pypdf import PdfReader

from app.services.assurance.rubric import ConfidenceReport, RubricDimension
from app.services.mitigation.gap_analysis import TechniqueGapAnalysis
from app.services.reporting.export_csv import export_csv, parse_csv
from app.services.reporting.export_json import export_json, report_data_to_dict
from app.services.reporting.export_otm import export_otm
from app.services.reporting.export_pdf import markdown_to_pdf_bytes
from app.services.reporting.models import ReportData
from app.services.reporting.otm_schema import validate_otm
from app.services.risk.models import CSFFunctionRollup, RiskFactors, RiskFinding
from app.services.systemmodel.models import Component, SystemModel, TrustZone


def _confidence():
    dim = RubricDimension(name="x", score=80.0, weight=1 / 6, raw_counts={}, detail="")
    return ConfidenceReport(dimensions=(dim,) * 6, overall_score=80.0, band="High")


def _finding(path_id="path-1", technique_ids=("T1190",), score=0.5, csf_functions=("PR",)):
    return RiskFinding(
        path_id=path_id, entry_point="client", target="db", technique_ids=technique_ids,
        tactic_sequence=("initial-access",), score=score,
        factors=RiskFactors(likelihood=0.5, impact_weight=0.75, statement_density=0.0, d3fend_gap_count=0, cri_gap_count=0, cri_mapping_absent=False),
        csf_functions=csf_functions, regulatory_exposure=(),
    )


def _gap(technique_id="T1190", cri_in_tier=("PR.AA-05.01",)):
    return TechniqueGapAnalysis(
        technique_id=technique_id, d3fend_required_ids=(), d3fend_observed_ids=(), d3fend_gap_ids=(),
        cri_mapping_absent=False, cri_in_tier_statement_ids=cri_in_tier, cri_gap_statement_ids=(),
        cri_mapping_inferred_fallback_ids=(),
    )


def _model():
    return SystemModel(
        id="p1", version=1, parent_version=None,
        trust_zones=[TrustZone(id="tz1", name="Zone", trust_rating=1)],
        components=[Component(id="client", name="Client", kind="external_entity", trust_zone_id="tz1"),
                    Component(id="db", name="DB", kind="datastore", trust_zone_id="tz1")],
    )


def _report_data(**overrides):
    defaults = {
        "project_name": "Demo", "business_criticality": "high", "model": _model(), "confidence": _confidence(),
        "risk_findings": (_finding(),), "csf_rollup": (CSFFunctionRollup("PR", 1, 1, 0, 0.0),),
        "tier": 3, "tier_justification": "Tier 3", "gaps": (_gap(),), "residual_risk": None, "roadmap": (),
        "recommendations": (), "adjudicated_threats": (), "rejection_log": (), "assumptions": (),
        "currency": None, "has_cri": True,
    }
    defaults.update(overrides)
    return ReportData(**defaults)


def test_export_json_is_deterministic_and_contains_key_fields():
    data = _report_data()
    first = export_json(data)
    second = export_json(data)
    assert first == second
    assert '"overall_score": 80.0' in first
    assert '"path_id": "path-1"' in first


def test_report_data_to_dict_round_trips_via_plain_dataclasses_asdict():
    data = _report_data()
    result = report_data_to_dict(data)
    assert result["project_name"] == "Demo"
    assert result["risk_findings"][0]["path_id"] == "path-1"


def test_export_csv_round_trips_ids_and_statement_references():
    data = _report_data()
    csv_text = export_csv(data)
    rows = parse_csv(csv_text)
    assert len(rows) == 1
    row = rows[0]
    assert row["finding_id"] == "path-1"
    assert row["technique_ids"] == ["T1190"]
    assert row["cri_statement_ids"] == ["PR.AA-05.01"]
    assert row["csf_functions"] == ["PR"]
    assert row["risk_score"] == pytest.approx(0.5)


def test_export_csv_handles_multiple_findings_and_multi_valued_cells():
    data = _report_data(
        risk_findings=(
            _finding(path_id="path-1", technique_ids=("T1190", "T1210"), csf_functions=("PR", "DE")),
            _finding(path_id="path-2", technique_ids=("T9999",), score=0.1, csf_functions=()),
        ),
        gaps=(_gap("T1190", ("PR.AA-05.01",)), _gap("T1210", ("DE.CM-01.01",))),
    )
    rows = parse_csv(export_csv(data))
    assert len(rows) == 2
    first = next(r for r in rows if r["finding_id"] == "path-1")
    assert set(first["technique_ids"]) == {"T1190", "T1210"}
    assert set(first["cri_statement_ids"]) == {"PR.AA-05.01", "DE.CM-01.01"}
    second = next(r for r in rows if r["finding_id"] == "path-2")
    assert second["cri_statement_ids"] == []


def test_export_otm_validates_against_the_authored_schema():
    document = export_otm(_model())
    validate_otm(document)  # must not raise
    assert document["otmVersion"] == "0.2.0"
    assert document["project"]["id"] == "p1"


def test_export_otm_rejects_a_malformed_document():
    with pytest.raises(jsonschema.ValidationError):
        validate_otm({"otmVersion": "0.2.0"})  # missing every other required key


def test_pdf_export_is_deterministic_given_identical_input():
    first = markdown_to_pdf_bytes("Executive Report", "Confidence: 80/100 (High)")
    second = markdown_to_pdf_bytes("Executive Report", "Confidence: 80/100 (High)")
    assert first == second


def test_pdf_export_differs_when_content_differs():
    v1 = markdown_to_pdf_bytes("Report v1", "some content")
    v2 = markdown_to_pdf_bytes("Report v2", "different content")
    assert v1 != v2


def test_pdf_export_is_valid_and_readable():
    pdf_bytes = markdown_to_pdf_bytes("Technical Report", "Line one\nConfidence: 80/100 (High)")
    reader = PdfReader(io.BytesIO(pdf_bytes))
    assert len(reader.pages) == 1
    text = reader.pages[0].extract_text()
    assert "Technical Report" in text
    assert "Confidence: 80/100 (High)" in text
