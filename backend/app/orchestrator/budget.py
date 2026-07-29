"""Per-agent tool-call budget.

Autonomous agent loops have a variable number of steps, unlike the flat
function-call pipeline this plan started from. Left unchecked, that's an
unbounded cost/latency risk, so every agent invocation gets a hard cap that
fails loudly rather than truncating silently — the same philosophy as the
attack-graph node/edge budget (Task 12).
"""

from __future__ import annotations


class BudgetExceededError(Exception):
    def __init__(self, agent_name: str, limit: int, tool_name: str) -> None:
        self.agent_name = agent_name
        self.limit = limit
        self.tool_name = tool_name
        super().__init__(
            f"agent {agent_name!r} exceeded its tool-call budget of {limit} "
            f"(over limit while calling tool {tool_name!r})"
        )


class AgentBudget:
    def __init__(self, agent_name: str, limit: int) -> None:
        self.agent_name = agent_name
        self.limit = limit
        self.calls = 0
        self.tool_names: list[str] = []

    def record_call(self, tool_name: str) -> None:
        self.calls += 1
        self.tool_names.append(tool_name)
        if self.calls > self.limit:
            raise BudgetExceededError(self.agent_name, self.limit, tool_name)
