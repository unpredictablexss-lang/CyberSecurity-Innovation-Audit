"""Versioned local API for the progressive triage policy settings."""

from __future__ import annotations

from typing import Any, Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .policy import (
    PRESETS,
    PolicyError,
    PolicyRevisionConflict,
    PolicyStore,
    PolicyStoreError,
    build_policy,
)


class PolicyUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    expected_revision: int = Field(ge=0, strict=True)
    profile: Literal["economical", "standard", "deep", "custom"]
    limits: dict[str, Any] | None = None
    family_quotas: bool | None = None


def _public_state(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "revision": state["revision"],
        "updated_at": state["updated_at"],
        "updated_by": state["updated_by"],
        "policy": state["policy"],
        "policy_sha256": state["policy_sha256"],
        "presets": PRESETS,
        "integration": {
            "grouping_and_ranking": "connected_to_multi_endpoint_operation_results",
            "worker_enforcement": "l2_l3_fixed_source_consent_and_parent_budget_gate",
            "quick_screen_executor": "independent_explicit_consent_operation",
            "task_budget_ledger": "shared_across_fixed_endpoints_for_l2_and_l3",
            "billing_hard_cap": False,
            "all_candidates_preserved": True,
            "task_level_consent_required": True,
        },
    }


def install_routes(app, data_dir) -> PolicyStore:
    """Register strict read/update routes and return the backing local store."""
    store = PolicyStore(data_dir)

    @app.get("/api/v1/agent/triage-policy")
    def get_triage_policy():
        try:
            return _public_state(store.read())
        except PolicyStoreError as error:
            raise HTTPException(status_code=500, detail=str(error)) from error

    @app.put("/api/v1/agent/triage-policy")
    def update_triage_policy(body: PolicyUpdate):
        try:
            policy = build_policy(body.profile, body.limits, body.family_quotas)
            state = store.update(policy, body.expected_revision)
        except PolicyRevisionConflict as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        except PolicyStoreError as error:
            raise HTTPException(status_code=500, detail=str(error)) from error
        except PolicyError as error:
            raise HTTPException(status_code=422, detail=str(error)) from error
        return _public_state(state)

    return store
