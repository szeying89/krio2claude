"""Shared validation for content-hash path segments.

Security-review finding: `content_hash` reaches every KB/CRI/intel
snapshot-lookup endpoint as a raw path parameter (or, for intel revision
inputs, a request-body string) and was joined directly onto a base
directory (`kb_dir / content_hash`, `cri_dir / content_hash`,
`intel_dir / content_hash`) with no format check. A value of `".."`
(reachable via the URL-encoded form `%2e%2e`, since a literal `..`
segment is normalized away by the ASGI router before it ever reaches
application code, but a percent-encoded one is decoded to `".."` only
*after* routing matches it as an opaque path-parameter value) resolves
one directory above the intended root. Every consumer's own
existence/precondition check (`Path.is_dir()`, `Path.exists()`) then
passes, because the *parent* directory obviously exists, and the bug
only actually surfaces several calls deeper as an unhandled
`FileNotFoundError` (a 500, not the clean 404 every one of these
endpoints otherwise returns for an unknown hash) once a loader function
tries to read a fixed filename (`manifest.json`, `techniques.json`, ...)
from that unintended parent directory. A content hash in this system is
always a lowercase sha256 hex digest — 64 hex characters — so rejecting
anything else up front, before any path join, closes the whole class of
input at its one shared choke point rather than hardening each
consumer's loader function individually.
"""

from __future__ import annotations

import re

_CONTENT_HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def is_valid_content_hash(value: str) -> bool:
    return bool(_CONTENT_HASH_RE.fullmatch(value))
