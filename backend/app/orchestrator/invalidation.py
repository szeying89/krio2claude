"""The single dependency/invalidation graph mechanism.

IMPLEMENTATION_PLAN.md is explicit that this replaces three previously
bespoke "re-run only what's affected" descriptions (a clarification answered,
a review item accepted, a threat-intel revision attached) with one code
path: given the set of artifact types that changed, compute the minimal set
of downstream agents that must re-run, by propagating through each agent's
declared input/output artifact types until reaching a fixed point.
"""

from __future__ import annotations

from app.orchestrator.registry import AgentRegistry


class InvalidationGraph:
    def __init__(self, registry: AgentRegistry) -> None:
        self.registry = registry

    def compute_affected(self, changed_artifact_types: set[str]) -> set[str]:
        """Return the names of every agent that must re-run given that the
        listed artifact types changed, including agents affected transitively
        because an upstream agent that feeds them was itself invalidated."""
        dirty_types = set(changed_artifact_types)
        affected_agents: set[str] = set()

        while True:
            newly_affected = {
                spec.name
                for spec in self.registry.all_specs()
                if spec.name not in affected_agents
                and set(spec.input_artifact_types) & dirty_types
            }
            if not newly_affected:
                return affected_agents

            affected_agents |= newly_affected
            for spec in self.registry.all_specs():
                if spec.name in newly_affected:
                    dirty_types |= set(spec.output_artifact_types)
