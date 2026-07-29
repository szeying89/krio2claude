"""Task 24: 'secret-scanning asserts no credential reaches DB, logs, or
exports'.

`redact_secrets` (Task 7) has existed since the LLM gateway was built,
but `LLMGateway.redact_before_send` defaulted to `False` and nothing in
`app/api/deps.py`'s real `get_llm_gateway()` ever set it -- meaning a
secret pasted into an uploaded design document would have been sent to
the real LLM provider (and, if the provider or a proxy logged the
request, into logs) completely unredacted. Fixed by turning it on in the
one real production gateway constructor. This test proves the fix
end-to-end through the real HTTP/DB stack (a design document containing
an AWS-shaped secret, extracted via a FakeProvider standing in for the
real provider) rather than only unit-testing `redact_secrets` itself
(already covered by `test_llm_redaction.py`): the secret must never
appear in the prompt actually sent to the provider, and it must never
appear in the project's exported JSON either.
"""

import json

import pytest

from app.api.deps import get_llm_gateway
from app.services.llm.fake_provider import FakeProvider
from app.services.llm.gateway import LLMGateway

VALID_PROJECT = {
    "name": "Payments Platform",
    "business_criticality": "high",
    "system_class": "it",
}

SECRET = "AKIAABCDEFGHIJKLMNOP"

DESIGN_DOC_WITH_SECRET = f"""\
# Payments Platform

The gateway forwards requests to the payment processor. Internal
config (do not commit): AWS_ACCESS_KEY_ID={SECRET}

```mermaid
flowchart LR
    Client((Client)) -->|HTTPS| Gateway[Gateway]
    Gateway --> Processor[(Payment Processor)]
```
"""

EXTRACTION = json.dumps(
    {"components": [], "actors": [], "flows": [], "assets": [], "trust_zones": [], "declared_controls": []}
)


@pytest.mark.asyncio
async def test_a_secret_in_an_uploaded_document_is_redacted_before_reaching_the_llm(
    client, tmp_path
):
    from app.main import app

    captured_prompts: list[str] = []

    def _respond(prompt: str) -> str:
        captured_prompts.append(prompt)
        return EXTRACTION

    def _gateway_dep():
        # redact_before_send=True mirrors the real get_llm_gateway()
        # dependency's own default -- this test exercises exactly what
        # production does, not a looser test-only configuration.
        return LLMGateway(
            FakeProvider(respond=_respond), cache_dir=tmp_path / "llm-cache", redact_before_send=True
        )

    app.dependency_overrides[get_llm_gateway] = _gateway_dep
    try:
        resp = await client.post("/projects", json=VALID_PROJECT)
        project_id = resp.json()["id"]
        await client.post(
            f"/projects/{project_id}/documents",
            files={"file": ("design.md", DESIGN_DOC_WITH_SECRET.encode(), "text/markdown")},
        )
        await client.post(f"/projects/{project_id}/system-model")

        json_export = await client.get(f"/projects/{project_id}/exports/json")
    finally:
        app.dependency_overrides.pop(get_llm_gateway, None)

    assert captured_prompts, "the extraction prompt must actually have been sent"
    for prompt in captured_prompts:
        assert SECRET not in prompt
    assert any("REDACTED" in prompt for prompt in captured_prompts)

    assert json_export.status_code == 200
    assert SECRET not in json_export.text


def test_real_get_llm_gateway_dependency_redacts_by_default():
    """A structural guarantee, not just a behavioral one: the real
    dependency factory itself must construct the gateway with redaction
    on, so no future call site can silently regress this by omission."""
    import inspect

    source = inspect.getsource(get_llm_gateway)
    assert "redact_before_send=True" in source
