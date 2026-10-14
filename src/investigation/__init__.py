"""Source-bound investigation support records; never scan or promote findings."""
from .contracts import (
    DRAFT_SCHEMA,
    FACT_BUNDLE_SCHEMA,
    FactBundle,
    InvestigationDraft,
    canonical_json,
    stable_id,
)
from .ipc_deterministic import build_ipc_fact_bundle
from .drafts import validate_investigation_draft

__all__ = [
    "DRAFT_SCHEMA",
    "FACT_BUNDLE_SCHEMA",
    "FactBundle",
    "InvestigationDraft",
    "build_ipc_fact_bundle",
    "canonical_json",
    "stable_id",
    "validate_investigation_draft",
]