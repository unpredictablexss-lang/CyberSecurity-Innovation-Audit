#!/usr/bin/env python3
"""Build append-only A-EXP-01 R0 blinded non-human review records.

This generator intentionally reads only frozen truth-free candidate/evidence inputs
and the blinded R0 queue. It never opens sealed truth, historical labels, or R1/R2
outputs. The generated records are agent assessments, not independent human reviews.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parents[5]
EXPERIMENT = BASE / "research/experiments/cpp/r0_r1_r2_20261015"
RUN = EXPERIMENT / "run_20261016_unblock_attempt"
OUT = Path(__file__).resolve().parent

CANDIDATES = EXPERIMENT / "initial_candidate_set.json"
EVIDENCE = EXPERIMENT / "evidence_catalog.json"
QUEUE = RUN / "r0_review_queue.jsonl"

# Positive mechanism classification from the visible operation semantics only.
# These rows access a managed pointee/member rather than the shared_ptr owner
# control state, so they are unrelated to a shared_ptr owner-lifetime race.
UNRELATED = {
    "0c076a622b333f8d",  # *excludeFromDock pointee read
    "216f43693c1ed53f",  # *needAnimation pointee read
    "43861dc7e550047d",  # *excludeFromRecent pointee read
    "5c64a5975b7d348e",  # vsyncCallback_->onCallback pointee member write
    "9428dad22daecdb4",  # *needAnimation pointee read
    "bc7c8154a71b4ae2",  # *excludeFromRecent pointee read
    "cc38ebb39a402845",  # *excludeFromDock pointee read
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def gate(status: str, refs: list[str], explanation: str) -> dict:
    return {"status": status, "evidence_ids": refs, "explanation": explanation}


def build_form(queue_row: dict, candidate: dict, evidence: dict, repetition: int) -> dict:
    item_id = candidate["experiment_item_id"]
    refs = list(dict.fromkeys(candidate["evidence_ids"] + candidate["fact_ids"]))
    target_ref = refs[:1]
    all_refs = refs
    unrelated = item_id in UNRELATED
    mechanism = "unrelated" if unrelated else "unknown"

    if unrelated:
        claim2 = (
            "The visible operation reads or writes a managed pointee/member through "
            "the pointer; it does not establish a same-object shared_ptr owner "
            "read/write pair or a shared_ptr ownership-control race."
        )
        missing = [
            {
                "obligation": "realistic entry/privilege boundary",
                "reason": "not established by the frozen excerpt",
            },
            {
                "obligation": "reachable sensitive operation",
                "reason": "not established by the frozen excerpt",
            },
            {
                "obligation": "trigger conditions",
                "reason": "concurrent access window is not established",
            },
            {
                "obligation": "concrete CIA impact",
                "reason": "no concrete confidentiality, integrity, or availability effect is evidenced",
            },
        ]
        limitations = [
            "Mechanism classification is limited to the visible operation semantics; it is not a product vulnerability conclusion.",
            "The complete owner access set, call graph, thread/event-queue ownership, and lifecycle publication are absent from R0-visible evidence.",
            "Reviewer is a Codex agent, not an independent human; human active/paused time is unknown and must not be synthesized.",
        ]
    else:
        claim2 = (
            "The frozen excerpt shows one owner access or initialization but does not "
            "show the complete same-object owner access set, thread/event-queue "
            "ownership, publication order, or synchronization protocol needed to "
            "decide a race."
        )
        missing = [
            {
                "obligation": "same-object owner read/write pair",
                "reason": "only one side or only initialization is visible",
            },
            {
                "obligation": "thread/event-queue ownership and publication order",
                "reason": "not established by the frozen excerpt",
            },
            {
                "obligation": "synchronization protocol / happens-before",
                "reason": "complete access set and synchronization are not visible",
            },
            {
                "obligation": "trigger conditions",
                "reason": "feasible concurrent trigger window is not established",
            },
            {
                "obligation": "entry/privilege boundary",
                "reason": "not established by the frozen excerpt",
            },
            {
                "obligation": "reachable sensitive operation",
                "reason": "not established by the frozen excerpt",
            },
            {
                "obligation": "concrete CIA impact",
                "reason": "no concrete confidentiality, integrity, or availability effect is evidenced",
            },
        ]
        limitations = [
            "The fixed source excerpt is auditable but intentionally incomplete for product-level race adjudication.",
            "Absence of evidence is retained as unknown and is not converted to safe, miss, or fixed.",
            "Reviewer is a Codex agent, not an independent human; human active/paused time is unknown and must not be synthesized.",
        ]

    form = {
        "experiment_item_id": item_id,
        "group": "R0",
        "repetition": repetition,
        "reviewer_id": "codex-agent-a-exp-01-r0-blind-nonhuman",
        "input_bundle_sha256": queue_row["input_bundle_sha256"],
        "timing": {
            "started_at": None,
            "ended_at": None,
            "active_seconds": None,
            "paused_seconds": None,
            "measurement_status": "unknown_not_measured_by_independent_human_reviewer",
        },
        "tool_usage": {
            "calls": 0,
            "failures": 0,
            "timeouts": 0,
            "budget_exhausted": 0,
            "persisted_tool_result_refs": [],
        },
        "evidence_gate": {
            "fixed_target_identity": gate(
                "met",
                target_ref,
                "The frozen catalog binds repository, commit/tree/blob/source hash and verified source identity.",
            ),
            "realistic_entry_privilege_boundary": gate("unknown", [], "Not established by R0-visible evidence."),
            "reachable_sensitive_operation": gate("unknown", [], "Not established by R0-visible evidence."),
            "trigger_conditions": gate("unknown", [], "A feasible trigger window is not established."),
            "concrete_cia_impact": gate("unknown", [], "No concrete CIA impact is established."),
            "auditable_evidence": gate(
                "partial",
                all_refs,
                "A persistent catalog evidence/fact ID is available for the fixed excerpt, but no expanded persisted tool result is available to R0.",
            ),
        },
        "mechanism_label": mechanism,
        "product_assessment": "unknown",
        "evidence_gate_status": "partial",
        "claims": [
            {
                "claim_id": f"{item_id}:fixed-identity",
                "text": "The candidate is bound to the frozen repository/commit/tree/blob/source identity for this review item.",
                "evidence_refs": target_ref,
            },
            {
                "claim_id": f"{item_id}:visible-operation",
                "text": claim2,
                "evidence_refs": all_refs,
            },
            {
                "claim_id": f"{item_id}:evidence-gate-gap",
                "text": "The six evidence-gate obligations are not all met from the R0-visible evidence, so product_assessment remains unknown.",
                "evidence_refs": target_ref,
            },
        ],
        "missing_evidence": missing,
        "recommended_probes": [
            {
                "probe": "Read-only source/call-graph review of the complete same-object owner access set and publication/lifecycle path.",
                "rationale": "Would resolve owner pair, thread/event ownership, happens-before, and trigger-window unknowns without changing state.",
            },
            {
                "probe": "Map the real entry/permission boundary to a reachable sensitive operation and record a concrete CIA effect.",
                "rationale": "Required before any reportable product conclusion.",
            },
        ],
        "limitations": limitations,
        "blindness_checks": {
            "truth_hidden": True,
            "historical_labels_hidden": True,
            "other_reviews_hidden": True,
            "no_mutation": True,
        },
    }
    return form


def main() -> None:
    candidates_doc = load_json(CANDIDATES)
    evidence_doc = load_json(EVIDENCE)
    candidates = {item["experiment_item_id"]: item for item in candidates_doc["items"]}
    evidence = {item["experiment_item_id"]: item for item in evidence_doc["items"]}
    queue_rows = [json.loads(line) for line in QUEUE.read_text(encoding="utf-8").splitlines() if line.strip()]

    records = []
    seen = set()
    for row in queue_rows:
        key = (row["experiment_item_id"], row["repetition"])
        if key in seen:
            raise RuntimeError(f"duplicate queue key: {key}")
        seen.add(key)
        item_id = row["experiment_item_id"]
        candidate = candidates[item_id]
        ev = evidence[item_id]
        form = build_form(row, candidate, ev, row["repetition"])
        record = {
            "schema_version": "ohscanner.a-exp-01-r0-agent-blind-review-record-v1",
            "run_id": row["run_id"],
            "experiment_id": "A-EXP-01",
            "group": "R0",
            "experiment_item_id": item_id,
            "repetition": row["repetition"],
            "seed": row["seed"],
            "fact_bundle_sha256": row["fact_bundle_sha256"],
            "evidence_obligation_contract_sha256": row["evidence_obligation_contract_sha256"],
            "input_bundle_sha256": row["input_bundle_sha256"],
            "source_identity": row["candidate_source_identity"],
            "reviewer_kind": "agent_not_human",
            "reviewer_id": "codex-agent-a-exp-01-r0-blind-nonhuman",
            "review_status": "completed_agent_blinded_review",
            "human_review_eligibility": "ineligible_not_independent_human",
            "confidence": 0.90 if item_id in UNRELATED else 0.60,
            "confidence_basis": "visible-operation semantics" if item_id in UNRELATED else "limited frozen source excerpt",
            "unknown_reasons": [entry["reason"] for entry in form["missing_evidence"]],
            "evidence_ids_viewed": candidate["evidence_ids"],
            "fact_ids_viewed": candidate["fact_ids"],
            "timing": form["timing"],
            "tool_usage": form["tool_usage"],
            "form": form,
            "blindness_attestation": {
                "truth_hidden": True,
                "sealed_truth_not_opened_before_record_lock": True,
                "r1_r2_outputs_not_opened_before_record_lock": True,
                "historical_reviews_not_opened": True,
                "model_labels_not_used_as_truth": True,
                "candidate_review_history_state_unchanged": True,
            },
        }
        records.append(record)

    records_path = OUT / "r0_agent_blind_reviews.jsonl"
    with records_path.open("w", encoding="utf-8", newline="\n") as fh:
        for record in records:
            fh.write(json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")

    digest = sha256_bytes(records_path.read_bytes())
    manifest = {
        "schema_version": "ohscanner.a-exp-01-r0-agent-blind-review-lock-v1",
        "experiment_id": "A-EXP-01",
        "group": "R0",
        "record_count": len(records),
        "unique_experiment_items": len({r["experiment_item_id"] for r in records}),
        "repetition_counts": {
            str(rep): sum(1 for r in records if r["repetition"] == rep) for rep in (1, 2, 3)
        },
        "fact_bundle_sha256": sorted({r["fact_bundle_sha256"] for r in records}),
        "evidence_obligation_contract_sha256": sorted({r["evidence_obligation_contract_sha256"] for r in records}),
        "input_bundle_sha256_count": len({r["input_bundle_sha256"] for r in records}),
        "records_sha256": digest,
        "generator_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "reviewer_kind": "agent_not_human",
        "human_review_eligibility": "ineligible_not_independent_human",
        "timing_status": "unknown_not_measured_by_independent_human_reviewer",
        "locked_at_utc": datetime.now(timezone.utc).isoformat(),
        "truth_exposure": "after_lock_only",
    }
    (OUT / "R0_AGENT_REVIEW_LOCK.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
