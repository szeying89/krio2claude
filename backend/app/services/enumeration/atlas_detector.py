"""ATLAS-matrix detector (Task 11): a deterministic, rule-based tool.

Per the plan: "ATLAS is added by user declaration or by a rule-based
detector tool ... whose proposals require user confirmation before
affecting enumeration — the Enumeration Agent can surface the proposal
but cannot silently enable ATLAS itself." This module only ever
*proposes*; nothing here writes to persisted state. The confirmation gate
lives in the API/db-service layer (`ProjectService`/`app/api/enumeration.py`),
which is the only path that can actually flip a project's `atlas_enabled`.

Whole-word matching, same reasoning as `app/services/systemmodel/
out_of_scope.py`: a bare substring check would false-positive (e.g. "api"
inside "rapid").
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from app.services.systemmodel.models import Component

_INDICATORS: dict[str, tuple[str, ...]] = {
    "model_serving": (
        "model serving",
        "model server",
        "torchserve",
        "triton inference server",
        "sagemaker endpoint",
        "seldon",
    ),
    "training_pipeline": (
        "training pipeline",
        "ml pipeline",
        "training job",
        "fine-tuning pipeline",
        "mlflow",
        "kubeflow",
    ),
    "inference_endpoint": (
        "inference endpoint",
        "inference api",
        "prediction endpoint",
        "model endpoint",
    ),
    "vector_store": (
        "vector store",
        "vector database",
        "embedding store",
        "pinecone",
        "weaviate",
        "faiss",
        "chroma",
        "milvus",
    ),
    "agent_framework": (
        "agent framework",
        "llm agent",
        "autogen",
        "langchain",
        "agentic workflow",
    ),
}


def _pattern_for(indicator: str) -> re.Pattern[str]:
    return re.compile(r"\b" + re.escape(indicator) + r"\b", re.IGNORECASE)


_PATTERNS: dict[str, list[tuple[str, re.Pattern[str]]]] = {
    category: [(indicator, _pattern_for(indicator)) for indicator in indicators]
    for category, indicators in _INDICATORS.items()
}


@dataclass(frozen=True)
class AtlasIndicatorFinding:
    subject_id: str
    category: str
    indicator: str


def detect_atlas_indicators(components: list[Component]) -> list[AtlasIndicatorFinding]:
    findings: list[AtlasIndicatorFinding] = []
    for component in components:
        haystack = " ".join((component.name, *component.technology_tags))
        for category, patterns in _PATTERNS.items():
            for indicator, pattern in patterns:
                if pattern.search(haystack):
                    findings.append(
                        AtlasIndicatorFinding(
                            subject_id=component.id, category=category, indicator=indicator
                        )
                    )
                    break  # one finding per (component, category) is enough to propose ATLAS
    return findings
