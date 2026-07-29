"""Attack graph construction (Task 12): a deterministic tool, built on top
of Task 10's STRIDE candidates and Task 11's CAPEC/ATT&CK bridge.

Nodes are `(entity, attacker_position, privilege_level)` triples. Edges are
technique-enabled transitions along the model's real dataflows, gated by
typed preconditions evaluated deterministically against the model — never
against agent judgment. Graph construction is a monotonic
label-correcting search (privilege only ever increases at a given
(entity, attacker_position) pair): a node is only (re-)expanded when a
transition reaches it at a *strictly higher* privilege than previously
recorded, which is what makes the graph acyclic by construction — a true
cycle would require a strand of transitions that never improves privilege
anywhere along the loop, and the search simply stops expanding as soon as
that happens.
"""

from __future__ import annotations

import enum
from collections import deque
from dataclasses import dataclass

import networkx as nx

from app.services.enumeration.bridge import TechniqueIndex, build_capec_bridge
from app.services.enumeration.engine import CandidateThreat
from app.services.systemmodel.models import Component, Dataflow, SystemModel

EXTERNAL_POSITION = "external"


class PrivilegeLevel(enum.IntEnum):
    NONE = 0
    USER = 1
    ADMIN = 2


@dataclass(frozen=True)
class AttackGraphNode:
    entity_id: str
    attacker_position: str
    privilege_level: PrivilegeLevel


@dataclass(frozen=True)
class Precondition:
    kind: str
    satisfied: bool
    detail: str


@dataclass(frozen=True)
class AttackGraphEdgeData:
    dataflow_id: str
    technique_id: str
    technique_name: str
    matrix: str
    capec_ids: tuple[str, ...]
    candidate_threat_id: str
    preconditions: tuple[Precondition, ...]
    citation: str


@dataclass(frozen=True)
class AttackGraph:
    graph: nx.MultiDiGraph
    entry_points: tuple[str, ...]
    crown_jewels: tuple[str, ...]


class AttackGraphBudgetExceededError(Exception):
    def __init__(self, kind: str, limit: int) -> None:
        self.kind = kind
        self.limit = limit
        super().__init__(f"attack graph {kind} budget of {limit} exceeded")


# --- Precondition predicates (each independently unit-tested) -------------


def check_reachability(flow: Dataflow | None) -> Precondition:
    if flow is None:
        return Precondition("reachability", False, "no dataflow connects these entities")
    return Precondition("reachability", True, f"reachable via dataflow {flow.id}")


def check_exposure(
    flow: Dataflow, from_external: bool, external_actor_ids: set[str]
) -> Precondition:
    if not from_external:
        return Precondition("exposure", True, "attacker already holds an internal foothold")
    if flow.source_id in external_actor_ids:
        return Precondition("exposure", True, "target is directly reachable from an external actor")
    return Precondition("exposure", False, "no external actor reaches this entity directly")


def check_authentication(
    flow: Dataflow, source_privilege: PrivilegeLevel, category: str
) -> Precondition:
    if not flow.authenticated:
        return Precondition("authentication", True, "no authentication required on this dataflow")
    if category == "spoofing":
        return Precondition(
            "authentication", True, "a spoofing technique forges the required identity"
        )
    if source_privilege >= PrivilegeLevel.USER:
        return Precondition(
            "authentication", True, "attacker already holds credentials from a prior foothold"
        )
    return Precondition(
        "authentication", False, "dataflow requires authentication the attacker does not yet have"
    )


def check_required_privilege(category: str, source_privilege: PrivilegeLevel) -> Precondition:
    if category != "elevation_of_privilege":
        return Precondition("required_privilege", True, "no minimum privilege required")
    if source_privilege >= PrivilegeLevel.USER:
        return Precondition(
            "required_privilege", True, "attacker already holds a foothold to escalate from"
        )
    return Precondition(
        "required_privilege", False, "elevation of privilege requires an existing foothold"
    )


def check_boundary_crossing(source_zone: str | None, target_zone: str | None) -> Precondition:
    crosses = source_zone != target_zone
    detail = "crosses a trust-zone boundary" if crosses else "stays within the same trust zone"
    return Precondition("boundary_crossing", True, detail)


def _next_privilege(category: str, source: PrivilegeLevel) -> PrivilegeLevel:
    if category == "elevation_of_privilege":
        return PrivilegeLevel.ADMIN
    return max(source, PrivilegeLevel.USER)


def build_attack_graph(
    model: SystemModel,
    dataflow_candidates: list[CandidateThreat],
    index: TechniqueIndex | None,
    allowed_matrices: tuple[str, ...] = ("enterprise",),
    node_budget: int = 500,
    edge_budget: int = 2000,
    techniques_per_transition: int = 3,
) -> AttackGraph:
    """`index` is optional: if no KB snapshot has ever been fetched (Task
    3), the graph still reports its entry points and crown jewels, just
    with zero technique-enabled edges — the bridge is an enrichment, not a
    dependency of the graph's structure."""
    components_by_id: dict[str, Component] = {c.id: c for c in model.components}
    out_of_scope_ids = {c.id for c in model.components if c.out_of_scope}
    external_actor_ids = {
        c.id for c in model.components if c.kind == "external_entity" and not c.out_of_scope
    }

    candidates_by_flow: dict[str, list[CandidateThreat]] = {}
    for candidate in dataflow_candidates:
        candidates_by_flow.setdefault(candidate.element_id, []).append(candidate)

    flows_by_source: dict[str, list[Dataflow]] = {}
    for flow in model.dataflows:
        if flow.source_id in out_of_scope_ids or flow.destination_id in out_of_scope_ids:
            continue
        flows_by_source.setdefault(flow.source_id, []).append(flow)

    graph: nx.MultiDiGraph = nx.MultiDiGraph()
    best_privilege: dict[tuple[str, str], PrivilegeLevel] = {}
    queue: deque[AttackGraphNode] = deque()

    def _seed(node: AttackGraphNode) -> None:
        key = (node.entity_id, node.attacker_position)
        if key in best_privilege:
            return
        best_privilege[key] = node.privilege_level
        if graph.number_of_nodes() >= node_budget:
            raise AttackGraphBudgetExceededError("node", node_budget)
        graph.add_node(node)
        queue.append(node)

    for actor_id in sorted(external_actor_ids):
        _seed(AttackGraphNode(actor_id, EXTERNAL_POSITION, PrivilegeLevel.NONE))

    while queue:
        current = queue.popleft()
        from_external = current.attacker_position == EXTERNAL_POSITION

        for flow in flows_by_source.get(current.entity_id, []):
            target_id = flow.destination_id
            target_component = components_by_id.get(target_id)
            if target_component is None:
                continue

            reach = check_reachability(flow)
            exposure = check_exposure(flow, from_external, external_actor_ids)
            if not (reach.satisfied and exposure.satisfied):
                continue

            if index is None:
                continue  # no KB snapshot to bridge against — no edges, structure still valid

            for candidate in candidates_by_flow.get(flow.id, []):
                auth = check_authentication(flow, current.privilege_level, candidate.category)
                req_priv = check_required_privilege(candidate.category, current.privilege_level)
                if not (auth.satisfied and req_priv.satisfied):
                    continue

                bridged = build_capec_bridge(
                    candidate.category,
                    "dataflow",
                    (),
                    index,
                    allowed_matrices=allowed_matrices,
                    top_k=techniques_per_transition,
                )
                if not bridged:
                    continue  # edges originate only from retrieved technique candidates

                target_privilege = _next_privilege(candidate.category, current.privilege_level)
                new_position = target_component.trust_zone_id
                key = (target_id, new_position)
                if key in best_privilege and best_privilege[key] >= target_privilege:
                    continue  # no improvement over an already-reached state

                is_new_state = best_privilege.get(key, PrivilegeLevel.NONE) < target_privilege
                best_privilege[key] = target_privilege
                target_node = AttackGraphNode(target_id, new_position, target_privilege)
                if target_node not in graph:
                    if graph.number_of_nodes() >= node_budget:
                        raise AttackGraphBudgetExceededError("node", node_budget)
                    graph.add_node(target_node)

                boundary = check_boundary_crossing(
                    components_by_id[current.entity_id].trust_zone_id, new_position
                )
                preconditions = (reach, exposure, auth, req_priv, boundary)

                for technique in bridged:
                    if graph.number_of_edges() >= edge_budget:
                        raise AttackGraphBudgetExceededError("edge", edge_budget)
                    graph.add_edge(
                        current,
                        target_node,
                        key=technique.technique_id,
                        data=AttackGraphEdgeData(
                            dataflow_id=flow.id,
                            technique_id=technique.technique_id,
                            technique_name=technique.technique_name,
                            matrix=technique.matrix,
                            capec_ids=technique.capec_ids,
                            candidate_threat_id=candidate.id,
                            preconditions=preconditions,
                            citation=index.description_by_technique.get(
                                technique.technique_id, ""
                            )[:280],
                        ),
                    )

                if is_new_state:
                    queue.append(target_node)

    entry_points = tuple(sorted(external_actor_ids))
    crown_jewels = tuple(sorted({a.owner_id for a in model.assets if a.owner_id}))
    return AttackGraph(graph=graph, entry_points=entry_points, crown_jewels=crown_jewels)
