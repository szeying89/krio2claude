"""Content-addressed, disk-persisted cache for LLM/agent gateway calls.

Keyed on hash(prompt + model_id + params + kb_snapshot_hash +
cri_snapshot_hash) per the plan. Persisted (unlike Task 1b's in-memory
orchestrator-level AgentInvocation cache) because the whole point here is
real cost/latency savings across process restarts, not just within a
single run.

The payload stored per key is an arbitrary JSON-serializable dict, so the
same primitive works for a single prompt/response pair (this gateway's
own use) or a full agent trajectory (ordered tool calls + final output,
once Task 8+ wires real agents through it) — this module doesn't care
about the payload's shape, only that it's deterministic given the key.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path
from typing import Any

from app.services.fs_permissions import FILE_MODE, secure_mkdir


def compute_cache_key(
    prompt: str,
    model: str,
    params: dict[str, Any],
    kb_snapshot_hash: str | None = None,
    cri_snapshot_hash: str | None = None,
) -> str:
    payload = {
        "prompt": prompt,
        "model": model,
        "params": params,
        "kb_snapshot_hash": kb_snapshot_hash,
        "cri_snapshot_hash": cri_snapshot_hash,
    }
    blob = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


class ContentAddressedCache:
    def __init__(self, cache_dir: Path) -> None:
        self.cache_dir = cache_dir

    def get(self, key: str) -> dict[str, Any] | None:
        path = self.cache_dir / f"{key}.json"
        if not path.is_file():
            return None
        return json.loads(path.read_text())

    def put(self, key: str, value: dict[str, Any]) -> None:
        # Security-review finding, fixed here: this cache holds the full
        # text of every prompt sent to the LLM and every raw completion
        # received -- project descriptions, DFD content, whatever
        # redact_secrets() didn't catch. It previously relied entirely on
        # its parent directory happening to already be locked down by
        # main.py's startup secure_mkdir; this makes the guarantee the
        # module's own, matching every other storage writer in the
        # codebase (kb/snapshot.py, cri/snapshot.py, intel/storage.py,
        # project_service.py).
        secure_mkdir(self.cache_dir, parents=True, exist_ok=True)
        path = self.cache_dir / f"{key}.json"
        if path.exists():
            return  # content-addressed: an existing entry for this key is already correct
        tmp_path = self.cache_dir / f".tmp-{key}-{uuid.uuid4().hex}.json"
        tmp_path.write_text(json.dumps(value, indent=2, sort_keys=True))
        tmp_path.chmod(FILE_MODE)
        tmp_path.rename(path)
