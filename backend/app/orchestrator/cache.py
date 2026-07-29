"""Content-addressed trajectory cache.

Keyed on hash(inputs + pinned snapshots + model/tool config). A cache hit
reproduces a prior agent trajectory byte-for-byte with zero tool calls —
this is what "identical reruns are byte-identical" means for agent-driven
stages (agents themselves are autonomous and not otherwise guaranteed to
behave identically run to run). Task 7 extends this into the persisted,
provider-facing LLM/agent gateway cache; this in-memory version is the
general mechanism the orchestrator itself depends on from Task 1b onward.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from app.orchestrator.contracts import TrajectoryRecord


def compute_cache_key(
    agent_name: str,
    input_artifacts: dict[str, Any],
    config: dict[str, Any],
    pinned_snapshots: dict[str, Any],
) -> str:
    payload = {
        "agent_name": agent_name,
        "input_artifacts": input_artifacts,
        "config": config,
        "pinned_snapshots": pinned_snapshots,
    }
    blob = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class TrajectoryCache:
    def __init__(self) -> None:
        self._store: dict[str, TrajectoryRecord] = {}

    def get(self, key: str) -> TrajectoryRecord | None:
        return self._store.get(key)

    def put(self, key: str, trajectory: TrajectoryRecord) -> None:
        self._store[key] = trajectory
