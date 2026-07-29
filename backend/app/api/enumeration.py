from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from app.api.deps import get_project_service, get_system_model_service
from app.core.config import get_settings
from app.orchestrator.orchestrator import Orchestrator, ValidationError
from app.orchestrator.registry import AgentRegistry
from app.services.enumeration.adjudication import Adjudication
from app.services.enumeration.agent import (
    AGENT_NAME as ENUMERATION_AGENT_NAME,
)
from app.services.enumeration.agent import (
    RejectionLogEntry,
    build_enumeration_agent,
    validate_enumeration_grounding,
)
from app.services.enumeration.atlas_detector import detect_atlas_indicators
from app.services.enumeration.attack_graph import (
    AttackGraph,
    AttackGraphBudgetExceededError,
    AttackGraphNode,
    Precondition,
    build_attack_graph,
)
from app.services.enumeration.bridge import (
    BridgedTechnique,
    TechniqueIndex,
    bridge_candidates,
    build_technique_index,
)
from app.services.enumeration.engine import enumerate_threats
from app.services.enumeration.matrix import EnumerationResult, build_enumeration_result
from app.services.enumeration.path_enumeration import (
    AttackPath,
    PathEnumerationBudgetExceededError,
    enumerate_paths,
)
from app.services.enumeration.ruleset import load_ruleset
from app.services.kb.snapshot import latest_snapshot_dir, read_techniques
from app.services.project_service import ProjectNotFoundError, ProjectService
from app.services.systemmodel.db_service import (
    ProjectSystemModelService,
    SystemModelNotFoundError,
)
from app.services.systemmodel.models import SystemModel

router = APIRouter(prefix="/projects", tags=["enumeration"])

_RULESET = load_ruleset()
_technique_indexes: dict[str, TechniqueIndex] = {}


def _get_technique_index() -> TechniqueIndex | None:
    """The CAPEC bridge needs a KB snapshot's real technique corpus; if none
    has ever been fetched (Task 3), enumeration still works — it simply
    returns STRIDE/LINDDUN candidates with no bridged techniques attached,
    rather than failing the whole request over a missing, optional bridge."""
    snapshot_dir = latest_snapshot_dir(get_settings().kb_dir)
    if snapshot_dir is None:
        return None
    key = snapshot_dir.name
    if key not in _technique_indexes:
        _technique_indexes[key] = build_technique_index(read_techniques(snapshot_dir))
    return _technique_indexes[key]


class BridgedTechniqueOut(BaseModel):
    technique_id: str
    technique_name: str
    matrix: str
    capec_ids: list[str]
    fused_score: float


class CandidateThreatOut(BaseModel):
    id: str
    element_id: str
    element_kind: str
    framework: str
    category: str
    ruleset_version: str
    bridged_techniques: list[BridgedTechniqueOut] = []


class ElementMatrixRowOut(BaseModel):
    element_id: str
    element_name: str
    element_kind: str
    stride_categories: list[str]
    linddun_categories: list[str]


class EnumerationResultOut(BaseModel):
    ruleset_version: str
    linddun_present: bool
    atlas_enabled: bool
    matrix: list[ElementMatrixRowOut]
    candidates: list[CandidateThreatOut]


def _bridged_out(techniques: list[BridgedTechnique]) -> list[BridgedTechniqueOut]:
    return [
        BridgedTechniqueOut(
            technique_id=t.technique_id,
            technique_name=t.technique_name,
            matrix=t.matrix,
            capec_ids=list(t.capec_ids),
            fused_score=t.fused_score,
        )
        for t in techniques
    ]


def _result_out(
    model: SystemModel, result: EnumerationResult, atlas_enabled: bool
) -> EnumerationResultOut:
    index = _get_technique_index()
    allowed_matrices = ("enterprise", "atlas") if atlas_enabled else ("enterprise",)
    bridged_by_candidate = (
        bridge_candidates(model, list(result.candidates), index, allowed_matrices=allowed_matrices)
        if index is not None
        else {}
    )

    return EnumerationResultOut(
        ruleset_version=result.ruleset_version,
        linddun_present=result.linddun_present,
        atlas_enabled=atlas_enabled,
        matrix=[
            ElementMatrixRowOut(
                element_id=row.element_id,
                element_name=row.element_name,
                element_kind=row.element_kind,
                stride_categories=list(row.stride_categories),
                linddun_categories=list(row.linddun_categories),
            )
            for row in result.matrix
        ],
        candidates=[
            CandidateThreatOut(
                id=c.id,
                element_id=c.element_id,
                element_kind=c.element_kind,
                framework=c.framework,
                category=c.category,
                ruleset_version=c.ruleset_version,
                bridged_techniques=_bridged_out(bridged_by_candidate.get(c.id, [])),
            )
            for c in result.candidates
        ],
    )


@router.get("/{project_id}/system-model/threats", response_model=EnumerationResultOut)
async def get_latest_enumeration(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> EnumerationResultOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    return _result_out(model, build_enumeration_result(model, _RULESET), project.atlas_enabled)


@router.get(
    "/{project_id}/system-model/versions/{version}/threats", response_model=EnumerationResultOut
)
async def get_enumeration_for_version(
    project_id: str,
    version: int,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> EnumerationResultOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_version(project_id, version)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="system model version not found") from exc
    return _result_out(model, build_enumeration_result(model, _RULESET), project.atlas_enabled)


class AtlasIndicatorFindingOut(BaseModel):
    subject_id: str
    category: str
    indicator: str


class AtlasProposalOut(BaseModel):
    atlas_enabled: bool
    proposed: bool
    findings: list[AtlasIndicatorFindingOut]


@router.get("/{project_id}/atlas-proposal", response_model=AtlasProposalOut)
async def get_atlas_proposal(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> AtlasProposalOut:
    """Runs the deterministic ML-indicator detector against the latest
    frozen model and reports what it found — this call has zero side
    effects. ATLAS is never enabled here; see atlas-confirmation."""
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc

    findings = detect_atlas_indicators(model.components)
    return AtlasProposalOut(
        atlas_enabled=project.atlas_enabled,
        proposed=len(findings) > 0,
        findings=[
            AtlasIndicatorFindingOut(subject_id=f.subject_id, category=f.category, indicator=f.indicator)
            for f in findings
        ],
    )


class AtlasConfirmationIn(BaseModel):
    enabled: bool


class AtlasConfirmationOut(BaseModel):
    atlas_enabled: bool


@router.post("/{project_id}/atlas-confirmation", response_model=AtlasConfirmationOut)
async def confirm_atlas(
    project_id: str,
    body: AtlasConfirmationIn,
    project_service: ProjectService = Depends(get_project_service),
) -> AtlasConfirmationOut:
    """The only path that can change whether ATLAS affects enumeration —
    an explicit user action, never a side effect of the detector running."""
    try:
        project = await project_service.update_project(project_id, atlas_enabled=body.enabled)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    return AtlasConfirmationOut(atlas_enabled=project.atlas_enabled)


class PreconditionOut(BaseModel):
    kind: str
    satisfied: bool
    detail: str


class AttackGraphNodeOut(BaseModel):
    entity_id: str
    attacker_position: str
    privilege_level: str


class AttackGraphEdgeOut(BaseModel):
    source: AttackGraphNodeOut
    target: AttackGraphNodeOut
    dataflow_id: str
    technique_id: str
    technique_name: str
    matrix: str
    capec_ids: list[str]
    candidate_threat_id: str
    preconditions: list[PreconditionOut]
    citation: str


class AttackGraphOut(BaseModel):
    nodes: list[AttackGraphNodeOut]
    edges: list[AttackGraphEdgeOut]
    entry_points: list[str]
    crown_jewels: list[str]


def _node_out(node: AttackGraphNode) -> AttackGraphNodeOut:
    return AttackGraphNodeOut(
        entity_id=node.entity_id,
        attacker_position=node.attacker_position,
        privilege_level=node.privilege_level.name,
    )


def _preconditions_out(preconditions: tuple[Precondition, ...]) -> list[PreconditionOut]:
    return [
        PreconditionOut(kind=p.kind, satisfied=p.satisfied, detail=p.detail) for p in preconditions
    ]


def _attack_graph_out(result: AttackGraph) -> AttackGraphOut:
    edges: list[AttackGraphEdgeOut] = []
    for source, target, edge_data in result.graph.edges(data=True):
        data = edge_data["data"]
        edges.append(
            AttackGraphEdgeOut(
                source=_node_out(source),
                target=_node_out(target),
                dataflow_id=data.dataflow_id,
                technique_id=data.technique_id,
                technique_name=data.technique_name,
                matrix=data.matrix,
                capec_ids=list(data.capec_ids),
                candidate_threat_id=data.candidate_threat_id,
                preconditions=_preconditions_out(data.preconditions),
                citation=data.citation,
            )
        )
    return AttackGraphOut(
        nodes=[_node_out(n) for n in result.graph.nodes],
        edges=edges,
        entry_points=list(result.entry_points),
        crown_jewels=list(result.crown_jewels),
    )


def _build_graph_for_model(model: SystemModel, atlas_enabled: bool) -> AttackGraph:
    index = _get_technique_index()
    allowed_matrices = ("enterprise", "atlas") if atlas_enabled else ("enterprise",)
    dataflow_candidates = [
        c
        for c in enumerate_threats(model, _RULESET)
        if c.element_kind == "dataflow" and c.framework == "stride"
    ]
    return build_attack_graph(model, dataflow_candidates, index, allowed_matrices=allowed_matrices)


@router.get("/{project_id}/system-model/attack-graph", response_model=AttackGraphOut)
async def get_latest_attack_graph(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> AttackGraphOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    try:
        return _attack_graph_out(_build_graph_for_model(model, project.atlas_enabled))
    except AttackGraphBudgetExceededError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/{project_id}/system-model/versions/{version}/attack-graph", response_model=AttackGraphOut
)
async def get_attack_graph_for_version(
    project_id: str,
    version: int,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> AttackGraphOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_version(project_id, version)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="system model version not found") from exc
    try:
        return _attack_graph_out(_build_graph_for_model(model, project.atlas_enabled))
    except AttackGraphBudgetExceededError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


class PathStepOut(BaseModel):
    source_entity_id: str
    target_entity_id: str
    category: str
    technique_id: str
    technique_name: str
    matrix: str
    tactic: str
    dataflow_id: str
    candidate_threat_id: str
    likelihood: float


class AttackPathOut(BaseModel):
    id: str
    entry_point: str
    target: str
    steps: list[PathStepOut]
    tactic_sequence: list[str]
    aggregate_likelihood: float


class PathEnumerationOut(BaseModel):
    paths: list[AttackPathOut]
    capped: bool


def _attack_path_out(path: AttackPath) -> AttackPathOut:
    return AttackPathOut(
        id=path.id,
        entry_point=path.entry_point,
        target=path.target,
        steps=[
            PathStepOut(
                source_entity_id=s.source_entity_id,
                target_entity_id=s.target_entity_id,
                category=s.category,
                technique_id=s.technique_id,
                technique_name=s.technique_name,
                matrix=s.matrix,
                tactic=s.tactic,
                dataflow_id=s.dataflow_id,
                candidate_threat_id=s.candidate_threat_id,
                likelihood=s.likelihood,
            )
            for s in path.steps
        ],
        tactic_sequence=list(path.tactic_sequence),
        aggregate_likelihood=path.aggregate_likelihood,
    )


def _enumerate_paths_for_model(model: SystemModel, atlas_enabled: bool) -> PathEnumerationOut:
    graph = _build_graph_for_model(model, atlas_enabled)
    result = enumerate_paths(graph, model)
    return PathEnumerationOut(
        paths=[_attack_path_out(p) for p in result.paths], capped=result.capped
    )


@router.get("/{project_id}/system-model/attack-paths", response_model=PathEnumerationOut)
async def get_latest_attack_paths(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> PathEnumerationOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    try:
        return _enumerate_paths_for_model(model, project.atlas_enabled)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.get(
    "/{project_id}/system-model/versions/{version}/attack-paths", response_model=PathEnumerationOut
)
async def get_attack_paths_for_version(
    project_id: str,
    version: int,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> PathEnumerationOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_version(project_id, version)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="system model version not found") from exc
    try:
        return _enumerate_paths_for_model(model, project.atlas_enabled)
    except (AttackGraphBudgetExceededError, PathEnumerationBudgetExceededError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


class InvalidationConditionOut(BaseModel):
    kind: str
    entity_id: str
    description: str


class AdjudicationOut(BaseModel):
    candidate_threat_id: str
    verdict: str
    rationale: str
    evidence_ref: str
    citation_score: float
    invalidation_condition: InvalidationConditionOut | None


class RejectionLogEntryOut(BaseModel):
    candidate_threat_id: str
    element_id: str
    category: str
    reason_code: str
    detail: str


class AdjudicationResultOut(BaseModel):
    candidate_count: int
    adjudicated_threats: list[AdjudicationOut]
    rejection_log: list[RejectionLogEntryOut]


def _adjudication_out(adjudication: Adjudication) -> AdjudicationOut:
    condition = adjudication.invalidation_condition
    return AdjudicationOut(
        candidate_threat_id=adjudication.candidate_threat_id,
        verdict=adjudication.verdict,
        rationale=adjudication.rationale,
        evidence_ref=adjudication.evidence_ref,
        citation_score=adjudication.citation_score,
        invalidation_condition=(
            InvalidationConditionOut(
                kind=condition.kind, entity_id=condition.entity_id, description=condition.description
            )
            if condition is not None
            else None
        ),
    )


def _rejection_out(entry: RejectionLogEntry) -> RejectionLogEntryOut:
    return RejectionLogEntryOut(
        candidate_threat_id=entry.candidate_threat_id,
        element_id=entry.element_id,
        category=entry.category,
        reason_code=entry.reason_code,
        detail=entry.detail,
    )


def _adjudicate_model(model: SystemModel, atlas_enabled: bool) -> AdjudicationResultOut:
    index = _get_technique_index()
    registry = AgentRegistry()
    registry.register(build_enumeration_agent(_RULESET, index))
    orchestrator = Orchestrator(registry, validate=validate_enumeration_grounding)
    result = orchestrator.invoke(
        ENUMERATION_AGENT_NAME, {"model": model, "atlas_enabled": atlas_enabled}
    )
    return AdjudicationResultOut(
        candidate_count=result.output_artifacts["candidate_count"],
        adjudicated_threats=[
            _adjudication_out(a) for a in result.output_artifacts["adjudicated_threats"]
        ],
        rejection_log=[_rejection_out(r) for r in result.output_artifacts["rejection_log"]],
    )


@router.get(
    "/{project_id}/system-model/adjudicated-threats", response_model=AdjudicationResultOut
)
async def get_latest_adjudicated_threats(
    project_id: str,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> AdjudicationResultOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_latest(project_id)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="no system model has been frozen yet") from exc
    try:
        return _adjudicate_model(model, project.atlas_enabled)
    except AttackGraphBudgetExceededError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=500, detail=f"central grounding gate rejected agent output: {exc}"
        ) from exc


@router.get(
    "/{project_id}/system-model/versions/{version}/adjudicated-threats",
    response_model=AdjudicationResultOut,
)
async def get_adjudicated_threats_for_version(
    project_id: str,
    version: int,
    project_service: ProjectService = Depends(get_project_service),
    model_service: ProjectSystemModelService = Depends(get_system_model_service),
) -> AdjudicationResultOut:
    try:
        project = await project_service.get_project(project_id)
    except ProjectNotFoundError as exc:
        raise HTTPException(status_code=404, detail="project not found") from exc
    try:
        model = await model_service.get_version(project_id, version)
    except SystemModelNotFoundError as exc:
        raise HTTPException(status_code=404, detail="system model version not found") from exc
    try:
        return _adjudicate_model(model, project.atlas_enabled)
    except AttackGraphBudgetExceededError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValidationError as exc:
        raise HTTPException(
            status_code=500, detail=f"central grounding gate rejected agent output: {exc}"
        ) from exc
