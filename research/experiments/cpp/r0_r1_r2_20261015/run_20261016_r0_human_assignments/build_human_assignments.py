#!/usr/bin/env python3
"""Build three blinded A-EXP-01 R0 assignments for independent human reviewers.

Reads only frozen truth-free inputs and the R0 queue. It never opens sealed truth,
historical labels, model outputs, R1/R2 outputs, or R2 tool results.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[5]
EXP = ROOT / "research/experiments/cpp/r0_r1_r2_20261015"
RUN = EXP / "run_20261016_unblock_attempt"
OUT = Path(__file__).resolve().parent

INPUTS = {
    "initial_candidate_set": EXP / "initial_candidate_set.json",
    "evidence_catalog": EXP / "evidence_catalog.json",
    "blind_review_packet": ROOT / "research/evidence/cpp/independent_review_20261015/blind_review_packet.json",
    "r0_review_queue": RUN / "r0_review_queue.jsonl",
}


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def dump(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    candidates_doc = load(INPUTS["initial_candidate_set"])
    evidence_doc = load(INPUTS["evidence_catalog"])
    packet_doc = load(INPUTS["blind_review_packet"])
    queue_rows = [json.loads(x) for x in INPUTS["r0_review_queue"].read_text(encoding="utf-8").splitlines() if x.strip()]

    candidates = {x["experiment_item_id"]: x for x in candidates_doc["items"]}
    evidence = {x["experiment_item_id"]: x for x in evidence_doc["items"]}
    packet = {x["blind_item_id"]: x for x in packet_doc["items"]}

    assert len(candidates) == len(evidence) == len(packet) == 45
    assert set(candidates) == set(evidence) == set(packet)
    assert Counter(x["repetition"] for x in queue_rows) == {1: 45, 2: 45, 3: 45}

    source_inputs = [
        {
            "role": role,
            "path": str(path.relative_to(ROOT)).replace("\\", "/"),
            "sha256": sha256(path),
            "bytes": path.stat().st_size,
        }
        for role, path in INPUTS.items()
    ]

    common_hashes = {
        "fact_bundle_sha256": sorted({x["fact_bundle_sha256"] for x in queue_rows}),
        "evidence_obligation_contract_sha256": sorted({x["evidence_obligation_contract_sha256"] for x in queue_rows}),
    }
    assert len(common_hashes["fact_bundle_sha256"]) == 1
    assert len(common_hashes["evidence_obligation_contract_sha256"]) == 1

    total_templates = 0
    assignments = []
    for repetition in (1, 2, 3):
        rows = sorted((x for x in queue_rows if x["repetition"] == repetition), key=lambda x: x["run_id"])
        assert len(rows) == 45
        assignment_dir = OUT / f"repetition_{repetition}"
        assignment_dir.mkdir(parents=True, exist_ok=True)

        items = []
        templates = []
        for queue_position, row in enumerate(rows, start=1):
            item_id = row["experiment_item_id"]
            candidate = candidates[item_id]
            ev = evidence[item_id]
            visible_item = {
                "schema_version": "ohscanner.a-exp-01-r0-human-visible-item-v1",
                "queue_position": queue_position,
                "run_id": row["run_id"],
                "experiment_id": row["experiment_id"],
                "group": "R0",
                "repetition": repetition,
                "seed": row["seed"],
                "experiment_item_id": item_id,
                "input_bundle_sha256": row["input_bundle_sha256"],
                "fact_bundle_sha256": row["fact_bundle_sha256"],
                "evidence_obligation_contract_sha256": row["evidence_obligation_contract_sha256"],
                "candidate_source_identity": row["candidate_source_identity"],
                "detector": candidate["detector"],
                "source_context": candidate["source_context"],
                "review_questions": candidate["review_questions"],
                "evidence_catalog_entry": ev,
                "blind_packet_item": packet[item_id],
                "required_blindness_checks": row["required_blindness_checks"],
                "prohibited": row["prohibited"],
            }
            items.append(visible_item)

            allowed_refs = sorted(set(candidate["evidence_ids"] + candidate["fact_ids"]))
            template = {
                "schema_version": "ohscanner.a-exp-01-r0-human-submission-wrapper-v1",
                "run_id": row["run_id"],
                "experiment_id": "A-EXP-01",
                "group": "R0",
                "experiment_item_id": item_id,
                "repetition": repetition,
                "seed": row["seed"],
                "fact_bundle_sha256": row["fact_bundle_sha256"],
                "evidence_obligation_contract_sha256": row["evidence_obligation_contract_sha256"],
                "input_bundle_sha256": row["input_bundle_sha256"],
                "allowed_evidence_refs": allowed_refs,
                "form": {
                    "experiment_item_id": item_id,
                    "group": "R0",
                    "repetition": repetition,
                    "reviewer_id": None,
                    "input_bundle_sha256": row["input_bundle_sha256"],
                    "timing": {
                        "started_at": None,
                        "ended_at": None,
                        "active_seconds": None,
                        "paused_seconds": None,
                        "measurement_status": "must_be_measured_by_human_reviewer",
                    },
                    "tool_usage": {
                        "calls": 0,
                        "failures": 0,
                        "timeouts": 0,
                        "budget_exhausted": 0,
                        "persisted_tool_result_refs": [],
                    },
                    "evidence_gate": {
                        "fixed_target_identity": {"status": None, "evidence_ids": [], "explanation": None},
                        "realistic_entry_privilege_boundary": {"status": None, "evidence_ids": [], "explanation": None},
                        "reachable_sensitive_operation": {"status": None, "evidence_ids": [], "explanation": None},
                        "trigger_conditions": {"status": None, "evidence_ids": [], "explanation": None},
                        "concrete_cia_impact": {"status": None, "evidence_ids": [], "explanation": None},
                        "auditable_evidence": {"status": None, "evidence_ids": [], "explanation": None},
                    },
                    "mechanism_label": None,
                    "product_assessment": None,
                    "evidence_gate_status": None,
                    "claims": [],
                    "missing_evidence": [],
                    "recommended_probes": [],
                    "limitations": [],
                    "blindness_checks": {
                        "truth_hidden": True,
                        "historical_labels_hidden": True,
                        "other_reviews_hidden": True,
                        "no_mutation": True,
                    },
                },
                "review_metadata": {
                    "reviewer_kind": "independent_human_required",
                    "reviewer_id": None,
                    "confidence": None,
                    "confidence_basis": None,
                    "evidence_ids_viewed": [],
                    "fact_ids_viewed": [],
                    "unknown_reasons": [],
                    "model_outputs_hidden": True,
                    "sealed_truth_hidden": True,
                    "synthetic_controls_not_used_as_truth": True,
                    "historical_reviews_not_used_as_truth": True,
                },
            }
            templates.append(template)
            total_templates += 1

        items_path = assignment_dir / "review_items.jsonl"
        templates_path = assignment_dir / "submission_template.jsonl"
        with items_path.open("w", encoding="utf-8", newline="\n") as fh:
            for item in items:
                fh.write(json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")
        with templates_path.open("w", encoding="utf-8", newline="\n") as fh:
            for template in templates:
                fh.write(json.dumps(template, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n")

        manifest = {
            "schema_version": "ohscanner.a-exp-01-r0-human-assignment-v1",
            "experiment_id": "A-EXP-01",
            "group": "R0",
            "repetition": repetition,
            "seed": rows[0]["seed"],
            "planned_reviews": 45,
            "status": "awaiting_independent_human_reviewer",
            "reviewer_id": None,
            "reviewer_kind_required": "independent_human",
            "timing_required_per_item": ["started_at", "ended_at", "active_seconds", "paused_seconds"],
            "common_hashes": common_hashes,
            "source_inputs": source_inputs,
            "items_sha256": sha256(items_path),
            "submission_template_sha256": sha256(templates_path),
            "blindness": {
                "sealed_truth_hidden": True,
                "historical_review_labels_hidden": True,
                "other_reviewer_answers_hidden": True,
                "r1_r2_outputs_hidden": True,
                "model_labels_hidden": True,
                "no_candidate_review_or_vulnerability_mutation": True,
            },
            "completion_rule": "Submit exactly 45 reviewed records; keep failures, abandoned, timeout, partial and unknown records with explicit reasons.",
            "metric_rule": "Do not compute TP/FP/FN/TN or Precision/Recall unless independent reliable truth and complete predictions are both available.",
        }
        dump(assignment_dir / "assignment_manifest.json", manifest)

        readme = f"""# A-EXP-01 R0 independent human assignment: repetition {repetition}

Status: awaiting independent human reviewer.

This package contains exactly 45 blinded review items and 45 blank submission wrappers. It is one repetition of the frozen 45-item experiment.

## Blindness

Do not open `sealed_item_key.json`, frozen truth labels, historical review labels, other reviewer answers, R1/R2 outputs, R2 tool results, or model labels before submitting. Do not modify candidate IDs, reviews, historical reports, cases, or vulnerability status.

## Execution

1. Use exactly one independent human reviewer for this repetition.
2. Review `review_items.jsonl` in the supplied order.
3. For every item, record `started_at`, `ended_at`, `active_seconds`, and `paused_seconds` from real observation. Never synthesize timing.
4. Record the exact `evidence_ids_viewed` and `fact_ids_viewed`.
5. Complete all six EvidenceObligations. Missing, partial, failed, timeout and unknown remain unknown.
6. Give a mechanism label, product assessment, confidence from 0 to 1, and explicit unknown reasons.
7. Save one completed wrapper per item as `submission.jsonl`, preserving failed, abandoned and timeout rows.
8. Run the validator from the assignment directory before sign-off.

The submission remains ineligible for accuracy metrics unless independent reliable truth is separately established. Model agreement, historical review and synthetic controls are not truth.
"""
        (assignment_dir / "README.md").write_text(readme, encoding="utf-8")
        assignments.append({
            "repetition": repetition,
            "seed": rows[0]["seed"],
            "directory": str(assignment_dir.relative_to(ROOT)).replace("\\", "/"),
            "planned_reviews": 45,
            "items_sha256": manifest["items_sha256"],
            "submission_template_sha256": manifest["submission_template_sha256"],
        })

    root_manifest = {
        "schema_version": "ohscanner.a-exp-01-r0-human-assignment-set-v1",
        "experiment_id": "A-EXP-01",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "status": "awaiting_three_independent_human_reviewers",
        "planned_total_reviews": total_templates,
        "review_items": 45,
        "repetitions": [1, 2, 3],
        "seeds": [20261015, 20261016, 20261017],
        "fact_bundle_sha256": common_hashes["fact_bundle_sha256"][0],
        "evidence_obligation_contract_sha256": common_hashes["evidence_obligation_contract_sha256"][0],
        "assignments": assignments,
        "source_inputs": source_inputs,
        "generator_sha256": sha256(Path(__file__)),
        "prohibited_sources_not_read": [
            "research/experiments/cpp/r0_r1_r2_20261015/sealed_item_key.json",
            "research/evidence/cpp/independent_review_20261015/blind_review_labels_frozen_20261015.json",
            "research/evidence/cpp/independent_review_20261015/independent_review_comparison_20261015.json",
            "research/evidence/cpp/independent_review_20261015/review_supplement.json",
            "research/experiments/cpp/r0_r1_r2_20261015/run_20261016_unblock_attempt/raw_model_requests",
            "research/experiments/cpp/r0_r1_r2_20261015/run_20261016_unblock_attempt/raw_model_responses",
            "research/experiments/cpp/r0_r1_r2_20261015/run_20261016_unblock_attempt/tool_results",
        ],
    }
    dump(OUT / "assignment_set_manifest.json", root_manifest)
    print(json.dumps(root_manifest, indent=2, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
