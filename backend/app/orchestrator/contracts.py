"""Core Orchestrator <-> Agent contract (IMPLEMENTATION_PLAN.md, Task 1b).

Deterministic engines and services are exposed to agents *as tools*, called
through AgentContext.call_tool. This is what keeps the plan's determinism and
grounding guarantees intact even though agents themselves are autonomous: an
agent decides *when* to call a tool, but the tool's own behavior (and the
central validation gate applied to its output) is never something the agent
can override.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from app.orchestrator.budget import AgentBudget


@dataclass(frozen=True)
class ToolCallRecord:
    tool_name: str
    args: tuple[Any, ...]
    kwargs: dict[str, Any]
    result: Any


@dataclass
class TrajectoryRecord:
    agent_name: str
    output_artifacts: dict[str, Any]
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    cache_hit: bool = False


class AgentContext:
    """Passed to an agent's handler. The only way a handler can affect the
    outside world is through call_tool — there is no other side channel."""

    def __init__(
        self,
        input_artifacts: dict[str, Any],
        config: dict[str, Any],
        pinned_snapshots: dict[str, Any],
        budget: AgentBudget,
    ) -> None:
        self.input_artifacts = input_artifacts
        self.config = config
        self.pinned_snapshots = pinned_snapshots
        self.budget = budget
        self.tool_calls: list[ToolCallRecord] = []

    def call_tool(self, tool_name: str, fn: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        self.budget.record_call(tool_name)
        result = fn(*args, **kwargs)
        self.tool_calls.append(ToolCallRecord(tool_name, args, kwargs, result))
        return result


AgentHandler = Callable[[AgentContext], dict[str, Any]]


@dataclass(frozen=True)
class AgentSpec:
    name: str
    input_artifact_types: tuple[str, ...]
    output_artifact_types: tuple[str, ...]
    handler: AgentHandler
    max_tool_calls: int = 50


@dataclass(frozen=True)
class AgentResult:
    status: str  # "complete" | "failed"
    output_artifacts: dict[str, Any]
    trajectory: TrajectoryRecord
    cache_hit: bool = False
