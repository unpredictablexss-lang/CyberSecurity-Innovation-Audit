"""Stable names and serialization helpers shared by the triage policy modules."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any


POLICY_VERSION = "progressive-triage-v2"
GROUPING_VERSION = "source-bound-groups-v1"
RANKING_VERSION = "evidence-family-rank-v1"
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
GIT_COMMIT_RE = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")


def canonical_json(value: Any) -> bytes:
    """Return the canonical UTF-8 representation used for reproducible hashes."""
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def content_sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()
