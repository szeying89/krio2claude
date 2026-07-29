from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_project_cri_service, get_project_service, get_system_model_service
from app.api.gap_context import cri_statements_with_bridge, get_kb_snapshot
from app.services.cri.db_service import CRIProfileNotUploadedError, ProjectCRIService
from app.services.enumeration.attack_graph import AttackGraphBudgetExceededError, build_attack_graph
from app.services.enumeration.engine import enumerate_threats
from app.services.enumeration.path_enumeration import (
    PathEnumerationBudgetExceededError,
    PathEnumerationResult,
    enumerate_paths,
)
from app.services.enumeration.ruleset import load_ruleset
from app.services.mitigation.gap_analysis import compute_technique_gaps, techniques_in_paths
from app.services.mitigation.inventory import build_control_inventory
from app.services.project_service import Project, ProjectNotFoundError, ProjectService
from app.services.risk.models import RiskRegister
from app.services.risk.register import build_risk_register
from app.services.systemmodel.db_service import (
    ProjectSystemModelService,
    SystemModelNotFoundError,
)
from app.services.systemmodel.models import SystemModel

router = APIRouter(prefix="/projects", tags=["risk"])

_RULESET = load_ruleset()


class RegulatoryExposureOut(BaseModel):
    short_code: str
    document_name: str
    issuing_organization: str


class RiskFactorsOut(BaseModel):
    likelihood: float
    impact_weight: float
    statement_density: float
    d3fend_gap_count: int
    cri_gap_count: int
    cri_mapping_absent: bool


class RiskFindingOut(BaseModel):
    path_id: str
    entry_point: str
    target: str
    technique_ids: list[str]
    tactic_sequence: list[str]
    score: float
    factors: RiskFactorsOut
    csf_functions: list[str]
    regulatory_exposure: list[RegulatoryExposureOut]


class CSFFunctionRollupOut(BaseModel):
    function: str
    technique_count: int
    in_tier_statement_count: int
    unsatisfied_statement_count: int
    unsatisfied_density: float


class RiskRegisterOut(BaseModel):
    degraded: bool
    tier: int | None
    findings: list[RiskFindingOut]
    csf_rollup: list[CSFFunctionRollupOut]


def _register_out(register: RiskRegister) -> RiskRegisterOut:
    return RiskRegisterOut(
        degraded=register.degraded,
        tier=register.tier,
        findings=[
            RiskFindingOut(
                path_id=f.path_id,
                entry_point=f.entry_point,
                target=f.target,
                technique_ids=list(f.technique_ids),
                tactic_sequence=list(f.tactic_sequence),
                score=f.score,
                factors=RiskFactorsOut(
                    likelihood=f.factors.likelihood,
                    impact_weight=f.factors.impact_weight,
                    statement_density=f.factors.statement_density,
                    d3fend_gap_count=f.factors.d3fend_gap_count,
                    cri_gap_count=f.factors.cri_gap_count,
                    cri_mapping_absent=f.factors.cri_mapping_absent,
                ),
                csf_functions=list(f.csf_functions),
                regulatory_exposure=[
                    RegulatoryExposureOut(
                        short_code=r.short_code,
                        document_name=r.document_name,
                        issuing_organization=r.issuing_organization,
                    )
                    for r in f.regulatory_exposure
                ],
            )
            for f in register.findings
        ],
        csf_rollup=[
            CSFFunctionRollupOut(
                function=r.function,
                technique_count=r.technique_count,
                in_tier_statement_count=r.in_tier_statement_count,
                unsatisfied_statement_count=r.unsatisfied_statement_count,
                unsatisfied_density=r.unsatisfied_density,
            )
            for r in register.csf_rollup
        ],
    )


async def _regulatory_documents(cri_service: ProjectCRIService, project_id: str) -> dict:
    try:
        return await cri_service.get_regulatory_documents(project_id)
    except CRIProfileNotUploadedError:
        return {}


async def _build_risk_register(
    project: Project,
    model: SystemModel,
    cri_service: ProjectCRIService,
) -> RiskRegisterOut:
    cri_statements = await cri_statements_with_bridge(cri_service, project.id)
    regulatory_documents = await _regulatory_documents(cri_service, project.id)
    tiering = await cri_service.get_tiering(project.id)
    tier = tiering.tier if tiering is not None else None

    snapshot = get_kb_snapshot()
    if snapshot is None:
        empty_result = PathEnumerationResult(paths=(), capped=False)
        register = build_risk_register(
            empty_result, [], project.business_criticality, tier, cri_statements, regulatory_documents
        )
        return _register_out(register)

    allowed_matrices = ("enterprise", "atlas") if project.atlas_enabled else ("enterprise",)
    dataflow_candidates = [
        c
        for c in enumerate_threats(model, _RULESET)
        if c.element_kind == "dataflow" and c.framework == "stride"
    ]
    graph = build_attack_graph(
        model, dataflow_candidates, snapshot.index, allowed_matrices=allowed_matrices
    )
    path_result = enumerate_paths(graph, model)
    technique_ids = techniques_in_paths(path_result)

    inventory = build_control_inventory(
        model.declared_controls, snapshot.d3fend_catalog, cri_statements
    )
    gaps = compute_technique_gaps(
        technique_ids, snapshot.techniques_by_id, inventory, cri_statements, tier
    )

    register = build_risk_register(
        path_result, gaps, project.business_criticality, tier, cri_statements, regulatory_documents
    )
    return _register_out(register)


@router.get("/{project_id}/system-model/risk-register", response_model=RiskRegisterOut)
async def get_latest_risk_register(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
) -> RiskRegisterOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    try:
        return await _build_risk_register(project, model, cri_service)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/{project_id}/system-model/versions/{version}/risk-register", response_model=RiskRegisterOut
)
async def get_risk_register_for_version(
    project_id: str,
    version: int,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
    cri_service: ProjectCRIService = Depends(get_project_cri_service),
) -> RiskRegisterOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_version(project_id, version)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="system model version not found") from exc
    try:
        return await _build_risk_register(project, model, cri_service)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
