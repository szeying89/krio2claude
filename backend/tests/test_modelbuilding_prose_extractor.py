import json

from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway
from app.services.llm.models import CompletionParams
from app.services.modelbuilding.prose_extractor import (
    PROSE_EXTRACTION_TEMPLATE,
    ProseExtractionResult,
    extract_prose_entities,
    number_lines,
)


def test_number_lines_is_one_indexed():
    numbered = number_lines("first\nsecond\nthird")
    assert numbered == "1: first\n2: second\n3: third"


def test_empty_prose_short_circuits_without_calling_the_provider(tmp_path):
    provider = FakeProvider(respond=lambda _p: '{"components": []}')
    gateway = LLMGateway(provider, cache_dir=tmp_path / "cache")
    result = extract_prose_entities(gateway, "   \n  ", CompletionParams(model="fake-model"))
    assert result == ProseExtractionResult()
    assert provider.calls == []


def test_extract_prose_entities_parses_a_full_response(tmp_path):
    canned = {
        "components": [
            {
                "name": "Auth Service",
                "kind": "process",
                "technology_tags": ["OAuth2"],
                "confidence": 0.9,
                "source_span": {"start_line": 2, "end_line": 2},
            }
        ],
        "actors": [
            {
                "name": "End User",
                "confidence": 0.95,
                "source_span": {"start_line": 1, "end_line": 1},
            }
        ],
        "flows": [
            {
                "source_name": "End User",
                "target_name": "Auth Service",
                "label": "logs in",
                "protocol": "HTTPS",
                "authenticated": True,
                "encrypted": True,
                "confidence": 0.8,
                "source_span": {"start_line": 3, "end_line": 3},
            }
        ],
        "assets": [],
        "trust_zones": [],
        "declared_controls": [],
    }
    provider = FakeProvider(respond=lambda _p: json.dumps(canned))
    gateway = LLMGateway(provider, cache_dir=tmp_path / "cache")

    result = extract_prose_entities(
        gateway, "The end user logs in to the Auth Service.", CompletionParams(model="fake-model")
    )
    assert len(result.components) == 1
    assert result.components[0].name == "Auth Service"
    assert result.components[0].technology_tags == ["OAuth2"]
    assert result.actors[0].name == "End User"
    assert result.flows[0].protocol == "HTTPS"
    # the prompt actually sent to the provider includes line-numbered prose
    assert "1: The end user logs in to the Auth Service." in provider.calls[0]


def test_prompt_template_is_versioned():
    assert PROSE_EXTRACTION_TEMPLATE.id == "prose_entity_extraction@1"
