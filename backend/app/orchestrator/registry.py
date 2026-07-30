from __future__ import annotations

from app.orchestrator.contracts import AgentSpec


class AgentNotRegisteredError(Exception):
    pass


class AgentRegistry:
    """Declarative registry of agents: name, scoped toolset contract, and
    declared input/output artifact types. This is what makes an agent
    invocable through the orchestrator's uniform AgentInvocation contract,
    and what the InvalidationGraph reads to know which agents consume and
    produce which artifact types."""

    def __init__(self) -> None:
        self._agents: dict[str, AgentSpec] = {}

    def register(self, spec: AgentSpec) -> None:
        self._agents[spec.name] = spec

    def get(self, name: str) -> AgentSpec:
        try:
            return self._agents[name]
        except KeyError as exc:
            raise AgentNotRegisteredError(name) from exc

    def __contains__(self, name: str) -> bool:
        return name in self._agents

    def all_specs(self) -> list[AgentSpec]:
        return list(self._agents.values())
