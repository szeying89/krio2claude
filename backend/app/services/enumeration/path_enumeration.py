"""Path enumeration with likelihood weighting (Task 13).

Yen's k-shortest-paths — networkx's `shortest_simple_paths`, which
enumerates simple paths in strictly increasing total-weight order — from
each in-scope external entry point to each crown-jewel (asset-owning)
component in Task 12's attack graph. `shortest_simple_paths` does not
support multigraphs, so the graph's parallel technique-edges between the
same two nodes are first collapsed onto a single simple `DiGraph`, keeping
only the lowest-weight (most likely) technique per hop — this collapse
*is* the "de-duplication of interchangeable-step variants" the plan
requires, not a separate pass.

Edge weight is `-log(likelihood)`, the standard transform that turns a
multiplicative chain of probabilities into an additive shortest-path
cost: minimizing the sum of `-log(likelihood)` along a path is exactly
maximizing the product of per-step likelihoods, so "shortest path" and
"most likely path" are the same computation.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass

import networkx as nx

from app.services.enumeration.attack_graph import AttackGraph, AttackGraphEdgeData, AttackGraphNode
from app.services.systemmodel.models import SystemModel

_MIN_LIKELIHOOD = 1e-6

# A documented heuristic, not an empirical statistic this platform has no
# source for: broad, generic STRIDE categories differ in how hard they
# typically are to pull off, all else equal. Same "visible default, never
# presented as ground truth" spirit as the rest of this plan's heuristics.
_CATEGORY_BASE_LIKELIHOOD: dict[str, float] = {
    "spoofing": 0.6,
    "tampering": 0.5,
    "repudiation": 0.4,
    "information_disclosure": 0.7,
    "denial_of_service": 0.6,
    "elevation_of_privilege": 0.3,
}
_DEFAULT_CATEGORY_LIKELIHOOD = 0.5


class PathEnumerationBudgetExceededError(Exception):
    def __init__(self, limit: int) -> None:
        self.limit = limit
        super().__init__(f"path enumeration search budget of {limit} candidates exceeded")


@dataclass(frozen=True)
class PathStep:
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


@dataclass(frozen=True)
class AttackPath:
    id: str
    entry_point: str
    target: str
    steps: tuple[PathStep, ...]
    tactic_sequence: tuple[str, ...]
    aggregate_likelihood: float


@dataclass(frozen=True)
class PathEnumerationResult:
    paths: tuple[AttackPath, ...]
    capped: bool  # True if k_per_target stopped enumeration before it was exhausted


def _exposure_factor(attacker_position: str) -> float:
    return 1.0 if attacker_position == "external" else 0.8


def _category_factor(category: str) -> float:
    return _CATEGORY_BASE_LIKELIHOOD.get(category, _DEFAULT_CATEGORY_LIKELIHOOD)


def _prevalence_factor(fused_score: float) -> float:
    """A documented proxy, not a real prevalence statistic this platform
    doesn't have: the retrieval relevance score behind the CAPEC bridge
    match (Task 11) scales with how strongly the technique's own
    description matches the category/context query, which correlates
    loosely with how on-point a technique is for this transition."""
    return max(0.1, min(1.0, fused_score * 20))


def _control_presence_factor(target_entity_id: str, controlled_entity_ids: set[str]) -> float:
    return 0.5 if target_entity_id in controlled_entity_ids else 1.0


def compute_step_likelihood(
    source_position: str,
    category: str,
    fused_score: float,
    target_entity_id: str,
    controlled_entity_ids: set[str],
    technique_id: str,
    intel_uplift: dict[str, float] | None = None,
) -> float:
    """The four named factors (exposure, required privilege, technique
    prevalence, control presence) multiplied into one per-step
    likelihood, then an optional per-technique `intel_uplift` multiplier —
    the seam a later Intel Agent (Task 18) plugs into without this
    function's signature or the rest of the pipeline changing."""
    likelihood = (
        _exposure_factor(source_position)
        * _category_factor(category)
        * _prevalence_factor(fused_score)
        * _control_presence_factor(target_entity_id, controlled_entity_ids)
    )
    if intel_uplift:
        likelihood *= intel_uplift.get(technique_id, 1.0)
    return max(_MIN_LIKELIHOOD, min(1.0, likelihood))


def _controlled_entity_ids(model: SystemModel) -> set[str]:
    ids: set[str] = set()
    for control in model.declared_controls:
        ids.update(control.applies_to_ids)
    return ids


EdgeInfo = dict[tuple[AttackGraphNode, AttackGraphNode], tuple[AttackGraphEdgeData, float]]


def _collapse_to_simple_graph(
    attack_graph: AttackGraph, model: SystemModel, intel_uplift: dict[str, float] | None
) -> tuple[nx.DiGraph, EdgeInfo]:
    controlled_entity_ids = _controlled_entity_ids(model)
    simple: nx.DiGraph = nx.DiGraph()
    edge_info: EdgeInfo = {}

    for source, target, edge_data in attack_graph.graph.edges(data=True):
        data = edge_data["data"]
        likelihood = compute_step_likelihood(
            source.attacker_position,
            data.category,
            data.fused_score,
            target.entity_id,
            controlled_entity_ids,
            data.technique_id,
            intel_uplift=intel_uplift,
        )
        key = (source, target)
        existing = edge_info.get(key)
        if existing is None or likelihood > existing[1]:
            edge_info[key] = (data, likelihood)
            simple.add_edge(source, target, weight=-math.log(likelihood))

    return simple, edge_info


def _path_id(entry_point: str, steps: tuple[PathStep, ...]) -> str:
    payload = entry_point + "|" + "|".join(
        f"{s.source_entity_id}>{s.technique_id}>{s.target_entity_id}" for s in steps
    )
    return "path-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


def _build_step(source: AttackGraphNode, target: AttackGraphNode, edge_info: EdgeInfo) -> PathStep:
    data, likelihood = edge_info[(source, target)]
    return PathStep(
        source_entity_id=source.entity_id,
        target_entity_id=target.entity_id,
        category=data.category,
        technique_id=data.technique_id,
        technique_name=data.technique_name,
        matrix=data.matrix,
        tactic=data.tactic,
        dataflow_id=data.dataflow_id,
        candidate_threat_id=data.candidate_threat_id,
        likelihood=likelihood,
    )


def enumerate_paths(
    attack_graph: AttackGraph,
    model: SystemModel,
    max_depth: int = 6,
    k_per_target: int = 3,
    search_budget: int = 5000,
    intel_uplift: dict[str, float] | None = None,
) -> PathEnumerationResult:
    simple, edge_info = _collapse_to_simple_graph(attack_graph, model, intel_uplift)
    crown_jewel_ids = set(attack_graph.crown_jewels)

    paths: list[AttackPath] = []
    overall_capped = False

    for entry_point in attack_graph.entry_points:
        source_nodes = [n for n in simple.nodes if n.entity_id == entry_point]
        target_nodes = [n for n in simple.nodes if n.entity_id in crown_jewel_ids]

        for source_node in source_nodes:
            for target_node in target_nodes:
                if target_node == source_node:
                    continue
                if not nx.has_path(simple, source_node, target_node):
                    continue

                found = 0
                iterations = 0
                for node_path in nx.shortest_simple_paths(
                    simple, source_node, target_node, weight="weight"
                ):
                    iterations += 1
                    if iterations > search_budget:
                        raise PathEnumerationBudgetExceededError(search_budget)
                    if len(node_path) - 1 > max_depth:
                        continue
                    if found >= k_per_target:
                        overall_capped = True
                        break

                    steps = tuple(
                        _build_step(node_path[i], node_path[i + 1], edge_info)
                        for i in range(len(node_path) - 1)
                    )
                    aggregate_likelihood = 1.0
                    for step in steps:
                        aggregate_likelihood *= step.likelihood

                    paths.append(
                        AttackPath(
                            id=_path_id(entry_point, steps),
                            entry_point=entry_point,
                            target=target_node.entity_id,
                            steps=steps,
                            tactic_sequence=tuple(s.tactic for s in steps),
                            aggregate_likelihood=aggregate_likelihood,
                        )
                    )
                    found += 1

    return PathEnumerationResult(paths=tuple(paths), capped=overall_capped)
