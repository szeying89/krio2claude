"""The Orchestrator: the deterministic control plane described in
IMPLEMENTATION_PLAN.md's "Orchestrator, Agent, and Service architecture".

It makes no LLM calls itself. It invokes agents through one uniform
contract, enforces every hard guarantee centrally (never by trusting an
agent's own restraint), and owns the trajectory cache and the
dependency/invalidation graph.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

from app.orchestrator.budget import AgentBudget
from app.orchestrator.cache import TrajectoryCache, compute_cache_key
from app.orchestrator.contracts import AgentContext, AgentResult, TrajectoryRecord
from app.orchestrator.invalidation import InvalidationGraph
from app.orchestrator.registry import AgentRegistry

logger = logging.getLogger(__name__)

ValidationGate = Callable[[str, dict[str, Any]], None]


class ValidationError(Exception):
    """Raised when an agent's output fails a centrally-enforced guarantee
    (schema, grounding, fact-provenance, ...). An agent cannot bypass this by
    its own judgment — the orchestrator checks every invocation's output,
    cache hit or not."""


class Orchestrator:
    def __init__(
        self,
        registry: AgentRegistry,
        validate: ValidationGate | None = None,
    ) -> None:
        self.registry = registry
        self.cache = TrajectoryCache()
        self.invalidation_graph = InvalidationGraph(registry)
        self._validate = validate

    def invoke(
        self,
        agent_name: str,
        input_artifacts: dict[str, Any],
        config: dict[str, Any] | None = None,
        pinned_snapshots: dict[str, Any] | None = None,
    ) -> AgentResult:
        config = config or {}
        pinned_snapshots = pinned_snapshots or {}
        spec = self.registry.get(agent_name)

        cache_key = compute_cache_key(agent_name, input_artifacts, config, pinned_snapshots)
        cached = self.cache.get(cache_key)
        if cached is not None:
            logger.info(
                "agent invoked: name=%s cache_hit=True tool_calls=%d latency_ms=0.0",
                agent_name,
                len(cached.tool_calls),
            )
            return AgentResult(
                status="complete",
                output_artifacts=cached.output_artifacts,
                trajectory=cached,
                cache_hit=True,
            )

        budget = AgentBudget(agent_name, spec.max_tool_calls)
        ctx = AgentContext(input_artifacts, config, pinned_snapshots, budget)
        started_at = time.perf_counter()
        output_artifacts = spec.handler(ctx)
        latency_ms = (time.perf_counter() - started_at) * 1000

        if self._validate is not None:
            self._validate(agent_name, output_artifacts)

        trajectory = TrajectoryRecord(
            agent_name=agent_name,
            output_artifacts=output_artifacts,
            tool_calls=list(ctx.tool_calls),
            cache_hit=False,
            latency_ms=latency_ms,
        )
        # Structured, greppable-per-agent logging (Task 24): cost per
        # invocation isn't captured here -- TrajectoryRecord/ToolCallRecord
        # don't currently propagate the LLM gateway's own per-call
        # GatewayResult (cost, token usage) up through a tool call's return
        # value, so this logs what is genuinely measurable at the
        # orchestrator boundary (wall-clock latency, tool-call count)
        # rather than fabricating a cost figure.
        logger.info(
            "agent invoked: name=%s cache_hit=False tool_calls=%d latency_ms=%.1f",
            agent_name,
            len(trajectory.tool_calls),
            latency_ms,
        )
        self.cache.put(cache_key, trajectory)
        return AgentResult(status="complete", output_artifacts=output_artifacts, trajectory=trajectory)

    def compute_affected(self, changed_artifact_types: set[str]) -> set[str]:
        return self.invalidation_graph.compute_affected(changed_artifact_types)
