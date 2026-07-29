import json

import pytest

from app.orchestrator.orchestrator import Orchestrator, ValidationError
from app.orchestrator.registry import AgentRegistry
from app.services.assurance.rubric import ConfidenceReport, RubricDimension
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.reporting.agent import (
    AGENT_NAME,
    build_reporting_agent,
    validate_reporting_fact_provenance,
)
from app.services.reporting.models import ReportData
from app.services.risk.models import CSFFunctionRollup, RiskFactors, RiskFinding
from app.services.systemmodel.models import Component, SystemModel, TrustZone

PARAMS = CompletionParams(model="fake-model")


def _confidence():
    dim = RubricDimension(name="x", score=72.0, weight=1 / 6, raw_counts={}, detail="")
    return ConfidenceReport(dimensions=(dim,) * 6, overall_score=72.0, band="Moderate")


def _model():
    return SystemModel(
        id="p1", version=1, parent_version=None,
        trust_zones=[TrustZone(id="tz1", name="Zone", trust_rating=1)],
        components=[Component(id="client", name="Client", kind="external_entity", trust_zone_id="tz1")],
    )


def _report_data():
    finding = RiskFinding(
        path_id="path-1", entry_point="client", target="db", technique_ids=("T1190",),
        tactic_sequence=("initial-access",), score=0.5,
        factors=RiskFactors(likelihood=0.5, impact_weight=0.75, statement_density=0.0, d3fend_gap_count=0, cri_gap_count=0, cri_mapping_absent=False),
        csf_functions=("PR",), regulatory_exposure=(),
    )
    return ReportData(
        project_name="Demo", business_criticality="high", model=_model(), confidence=_confidence(),
        risk_findings=(finding,), csf_rollup=(CSFFunctionRollup("PR", 1, 1, 0, 0.0),),
        tier=None, tier_justification="not computed", gaps=(), residual_risk=None, roadmap=(),
        recommendations=(), adjudicated_threats=(), rejection_log=(), assumptions=(), currency=None,
        has_cri=False,
    )


def _registry_and_orchestrator(gateway):
    registry = AgentRegistry()
    registry.register(build_reporting_agent(gateway, PARAMS))
    return Orchestrator(registry, validate=validate_reporting_fact_provenance)


def test_reporting_agent_produces_all_three_grounded_narratives(tmp_path):
    response = json.dumps({"summary": "This model shows T1190 as the leading risk driver."})
    gateway = LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "cache")
    orchestrator = _registry_and_orchestrator(gateway)

    result = orchestrator.invoke(AGENT_NAME, {"report_data": _report_data()})
    narratives = result.output_artifacts["narratives"]
    assert set(narratives) == {"executive", "ciso", "technical"}
    assert result.output_artifacts["rejection_log"] == []


def test_fabricated_technique_id_in_narrative_is_rejected_inline(tmp_path):
    response = json.dumps({"summary": "The real driver is fabricated technique T9999."})
    gateway = LLMGateway(FakeProvider(respond=lambda _p: response), cache_dir=tmp_path / "cache")
    orchestrator = _registry_and_orchestrator(gateway)

    result = orchestrator.invoke(AGENT_NAME, {"report_data": _report_data()})
    assert result.output_artifacts["narratives"] == {}
    assert len(result.output_artifacts["rejection_log"]) == 3
    assert all("T9999" in r["detail"] for r in result.output_artifacts["rejection_log"])


def test_validate_gate_independently_catches_a_hand_constructed_fabricated_narrative():
    data = _report_data()
    with pytest.raises(ValidationError):
        validate_reporting_fact_provenance(
            "reporting",
            {"report_data": data, "narratives": {"executive": "driven by T9999"}, "rejection_log": []},
        )


def test_validate_gate_passes_well_formed_output_through_untouched():
    data = _report_data()
    validate_reporting_fact_provenance(
        "reporting",
        {"report_data": data, "narratives": {"executive": "driven by T1190"}, "rejection_log": []},
    )
