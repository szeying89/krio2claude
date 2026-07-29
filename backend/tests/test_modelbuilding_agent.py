import json

from app.orchestrator.contracts import AgentResult
from app.orchestrator.orchestrator import Orchestrator
from app.orchestrator.registry import AgentRegistry
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.modelbuilding.agent import AGENT_NAME, build_model_building_agent
from app.services.modelbuilding.models import SystemModelDraft

MERMAID_SOURCE = """graph TD
    U((User))
    A[Auth Service]
    D[(User DB)]
    U -->|login| A
    A -->|query| D
"""

EMPTY_EXTRACTION = json.dumps(
    {
        "components": [],
        "actors": [],
        "flows": [],
        "assets": [],
        "trust_zones": [],
        "declared_controls": [],
    }
)


def _registry_and_gateway(tmp_path, respond=None):
    provider = FakeProvider(respond=respond or (lambda _p: EMPTY_EXTRACTION))
    gateway = LLMGateway(provider, cache_dir=tmp_path / "cache")
    params = CompletionParams(model="fake-model")
    registry = AgentRegistry()
    registry.register(build_model_building_agent(gateway, params))
    return registry, gateway, provider


def test_agent_merges_mermaid_and_prose_and_records_tool_calls(tmp_path):
    registry, _gateway, provider = _registry_and_gateway(tmp_path)
    orchestrator = Orchestrator(registry)

    input_artifacts = {
        "documents": [
            {
                "document_id": "doc1",
                "prose": "The User authenticates against the Auth Service.",
                "mermaid_sources": [MERMAID_SOURCE],
            }
        ]
    }
    result: AgentResult = orchestrator.invoke(AGENT_NAME, input_artifacts)

    assert result.status == "complete"
    draft = result.output_artifacts["system_model_draft"]
    assert isinstance(draft, SystemModelDraft)
    assert {c.name for c in draft.components} == {"Auth Service", "User DB"}
    assert {a.name for a in draft.actors} == {"User"}
    assert len(draft.flows) == 2

    tool_names = [call.tool_name for call in result.trajectory.tool_calls]
    assert "mermaid.parse_diagram" in tool_names
    assert "modelbuilding.add_diagram" in tool_names
    assert "llm.extract_prose_entities" in tool_names
    assert "modelbuilding.add_prose_extraction" in tool_names
    assert "modelbuilding.check_completeness" in tool_names
    assert len(provider.calls) == 1


def test_agent_flags_needs_input_when_completeness_gate_fires(tmp_path):
    prose_with_unclassified_asset = json.dumps(
        {
            "components": [],
            "actors": [],
            "flows": [],
            "assets": [
                {
                    "name": "Session Token",
                    "confidence": 0.7,
                    "source_span": {"start_line": 1, "end_line": 1},
                }
            ],
            "trust_zones": [],
            "declared_controls": [],
        }
    )
    registry, _gateway, _provider = _registry_and_gateway(
        tmp_path, respond=lambda _p: prose_with_unclassified_asset
    )
    orchestrator = Orchestrator(registry)

    input_artifacts = {
        "documents": [{"document_id": "doc1", "prose": "We store a session token.", "mermaid_sources": []}]
    }
    result = orchestrator.invoke(AGENT_NAME, input_artifacts)
    draft = result.output_artifacts["system_model_draft"]
    assert draft.needs_input is True
    assert draft.completeness_findings[0].kind == "unclassified_asset"


def test_agent_tolerates_a_malformed_mermaid_block_and_continues_with_prose(tmp_path):
    registry, _gateway, _provider = _registry_and_gateway(tmp_path)
    orchestrator = Orchestrator(registry)

    input_artifacts = {
        "documents": [
            {
                "document_id": "doc1",
                "prose": "Some prose describing the system.",
                "mermaid_sources": ["not a valid mermaid diagram at all {{{"],
            }
        ]
    }
    result = orchestrator.invoke(AGENT_NAME, input_artifacts)
    draft = result.output_artifacts["system_model_draft"]
    assert any(a.kind == "default" and "failed to parse" in a.message for a in draft.assumptions)


def test_agent_result_is_cached_on_identical_inputs(tmp_path):
    registry, _gateway, provider = _registry_and_gateway(tmp_path)
    orchestrator = Orchestrator(registry)
    input_artifacts = {
        "documents": [
            {"document_id": "doc1", "prose": "The service talks to the database.", "mermaid_sources": []}
        ]
    }

    first = orchestrator.invoke(AGENT_NAME, input_artifacts)
    second = orchestrator.invoke(AGENT_NAME, input_artifacts)

    assert first.cache_hit is False
    assert second.cache_hit is True
    assert len(provider.calls) == 1


def test_agent_with_no_documents_returns_empty_draft(tmp_path):
    registry, _gateway, provider = _registry_and_gateway(tmp_path)
    orchestrator = Orchestrator(registry)
    result = orchestrator.invoke(AGENT_NAME, {"documents": []})
    draft = result.output_artifacts["system_model_draft"]
    assert draft.components == []
    assert draft.completeness_findings == []
    assert provider.calls == []
