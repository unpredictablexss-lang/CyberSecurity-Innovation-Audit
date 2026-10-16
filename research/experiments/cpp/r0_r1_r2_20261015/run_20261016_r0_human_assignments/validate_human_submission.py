#!/usr/bin/env python3
"""Validate an A-EXP-01 R0 independent-human submission.

Usage:
  python validate_human_submission.py --assignment repetition_1 --submission submission.jsonl
  python validate_human_submission.py --assignment repetition_1 --package-only
  python validate_human_submission.py --assignment repetition_1 --submission submission.jsonl --peer-reviewer-ids id2,id3
"""
from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path

BASE = Path(__file__).resolve().parent
VALID_GATE_STATUS = {"met", "partial", "not_met", "unknown"}
VALID_MECHANISM = {"vulnerable", "fixed", "safe", "unrelated", "unknown"}
VALID_PRODUCT = {"reportable_vulnerability", "not_reportable", "unknown"}
VALID_GATE_KEYS = {
    "fixed_target_identity",
    "realistic_entry_privilege_boundary",
    "reachable_sensitive_operation",
    "trigger_conditions",
    "concrete_cia_impact",
    "auditable_evidence",
}


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_jsonl(path: Path):
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def parse_time(value, field, errors):
    if not isinstance(value, str) or not value:
        errors.append(f"{field} must be a non-empty ISO-8601 timestamp")
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        errors.append(f"{field} is not ISO-8601")
        return None


def validate_record(row: dict, template: dict, errors: list[str]) -> None:
    run_id = row.get("run_id", "<missing>")
    prefix = f"{run_id}: "
    for key in ("experiment_id", "group", "experiment_item_id", "repetition", "seed", "input_bundle_sha256", "fact_bundle_sha256", "evidence_obligation_contract_sha256"):
        if row.get(key) != template.get(key):
            errors.append(prefix + f"{key} does not match the frozen assignment")

    form = row.get("form")
    metadata = row.get("review_metadata")
    if not isinstance(form, dict):
        errors.append(prefix + "form is missing")
        return
    if not isinstance(metadata, dict):
        errors.append(prefix + "review_metadata is missing")
        return

    reviewer_id = form.get("reviewer_id")
    if not isinstance(reviewer_id, str) or not reviewer_id.strip():
        errors.append(prefix + "form.reviewer_id must identify the human reviewer")
    if metadata.get("reviewer_id") != reviewer_id:
        errors.append(prefix + "review_metadata.reviewer_id must match form.reviewer_id")
    if metadata.get("reviewer_kind") != "independent_human_required":
        errors.append(prefix + "review_metadata.reviewer_kind must remain independent_human_required")

    timing = form.get("timing", {})
    started = parse_time(timing.get("started_at"), prefix + "timing.started_at", errors)
    ended = parse_time(timing.get("ended_at"), prefix + "timing.ended_at", errors)
    if started and ended and ended < started:
        errors.append(prefix + "timing.ended_at precedes started_at")
    for field in ("active_seconds", "paused_seconds"):
        value = timing.get(field)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            errors.append(prefix + f"timing.{field} must be a nonnegative measured number")
    if timing.get("measurement_status") != "measured_by_human_reviewer":
        errors.append(prefix + "timing.measurement_status must be measured_by_human_reviewer")

    allowed_refs = set(template.get("allowed_evidence_refs", []))
    gate = form.get("evidence_gate", {})
    if set(gate) != VALID_GATE_KEYS:
        errors.append(prefix + "evidence_gate must contain exactly the six frozen obligations")
    for key, value in gate.items():
        if not isinstance(value, dict):
            errors.append(prefix + f"evidence_gate.{key} must be an object")
            continue
        if value.get("status") not in VALID_GATE_STATUS:
            errors.append(prefix + f"evidence_gate.{key}.status is invalid")
        refs = value.get("evidence_ids")
        if not isinstance(refs, list) or not refs:
            errors.append(prefix + f"evidence_gate.{key}.evidence_ids must be non-empty")
        else:
            for ref in refs:
                if ref not in allowed_refs:
                    errors.append(prefix + f"evidence_gate.{key} has out-of-scope ref {ref}")
        if not value.get("explanation"):
            errors.append(prefix + f"evidence_gate.{key}.explanation is required")

    if form.get("mechanism_label") not in VALID_MECHANISM:
        errors.append(prefix + "mechanism_label is invalid")
    if form.get("product_assessment") not in VALID_PRODUCT:
        errors.append(prefix + "product_assessment is invalid")
    if form.get("evidence_gate_status") not in VALID_GATE_STATUS:
        errors.append(prefix + "evidence_gate_status is invalid")
    if form.get("product_assessment") == "reportable_vulnerability" and form.get("evidence_gate_status") != "met":
        errors.append(prefix + "reportable_vulnerability requires evidence_gate_status=met")

    claims = form.get("claims")
    if not isinstance(claims, list) or not claims:
        errors.append(prefix + "at least one claim is required")
    else:
        for index, claim in enumerate(claims):
            if not isinstance(claim, dict) or not claim.get("claim_id") or not claim.get("text"):
                errors.append(prefix + f"claims[{index}] needs claim_id and text")
                continue
            refs = claim.get("evidence_refs")
            if not isinstance(refs, list) or not refs:
                errors.append(prefix + f"claims[{index}].evidence_refs must be non-empty")
            else:
                for ref in refs:
                    if ref not in allowed_refs:
                        errors.append(prefix + f"claims[{index}] has out-of-scope ref {ref}")

    missing = form.get("missing_evidence")
    if not isinstance(missing, list):
        errors.append(prefix + "missing_evidence must be an array")
    if form.get("evidence_gate_status") in {"partial", "not_met", "unknown"} and not missing:
        errors.append(prefix + "non-met/partial/unknown gate requires missing_evidence entries")

    confidence = metadata.get("confidence")
    if not isinstance(confidence, (int, float)) or isinstance(confidence, bool) or not 0 <= confidence <= 1:
        errors.append(prefix + "confidence must be between 0 and 1")
    if not metadata.get("confidence_basis"):
        errors.append(prefix + "confidence_basis is required")

    viewed_evidence = metadata.get("evidence_ids_viewed")
    viewed_facts = metadata.get("fact_ids_viewed")
    if not isinstance(viewed_evidence, list) or not viewed_evidence:
        errors.append(prefix + "evidence_ids_viewed must be non-empty")
    if not isinstance(viewed_facts, list) or not viewed_facts:
        errors.append(prefix + "fact_ids_viewed must be non-empty")
    for ref in (viewed_evidence or []) + (viewed_facts or []):
        if ref not in allowed_refs:
            errors.append(prefix + f"viewed reference is out of scope: {ref}")

    if form.get("mechanism_label") == "unknown" and not metadata.get("unknown_reasons"):
        errors.append(prefix + "unknown mechanism requires explicit unknown_reasons")
    for key in ("model_outputs_hidden", "sealed_truth_hidden", "synthetic_controls_not_used_as_truth", "historical_reviews_not_used_as_truth"):
        if metadata.get(key) is not True:
            errors.append(prefix + f"review_metadata.{key} must be true")

    checks = form.get("blindness_checks", {})
    for key in ("truth_hidden", "historical_labels_hidden", "other_reviews_hidden", "no_mutation"):
        if checks.get(key) is not True:
            errors.append(prefix + f"blindness_checks.{key} must be true")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assignment", required=True)
    parser.add_argument("--submission")
    parser.add_argument("--package-only", action="store_true")
    parser.add_argument("--peer-reviewer-ids", default="")
    args = parser.parse_args()

    assignment_dir = BASE / args.assignment
    manifest = load_json(assignment_dir / "assignment_manifest.json")
    templates = load_jsonl(assignment_dir / "submission_template.jsonl")
    items = load_jsonl(assignment_dir / "review_items.jsonl")
    errors: list[str] = []

    if len(items) != 45 or len(templates) != 45:
        errors.append("assignment must contain exactly 45 items and 45 templates")
    expected_runs = {x["run_id"] for x in items}
    template_runs = {x["run_id"] for x in templates}
    if expected_runs != template_runs:
        errors.append("review_items and submission_template run IDs differ")
    if manifest.get("status") != "awaiting_independent_human_reviewer":
        errors.append("assignment_manifest.status must remain awaiting_independent_human_reviewer before submission")

    result = {
        "schema_version": "ohscanner.a-exp-01-r0-human-submission-validation-v1",
        "assignment": args.assignment,
        "repetition": manifest.get("repetition"),
        "mode": "package_only" if args.package_only or not args.submission else "submission",
        "planned_reviews": 45,
        "validated_reviews": 0,
        "errors": errors,
    }

    if not args.package_only and args.submission:
        submission_path = Path(args.submission)
        if not submission_path.is_absolute():
            submission_path = assignment_dir / submission_path
        submission = load_jsonl(submission_path)
        by_run = {x.get("run_id"): x for x in submission}
        if len(submission) != 45:
            errors.append(f"submission must contain exactly 45 records, found {len(submission)}")
        if set(by_run) != expected_runs:
            errors.append("submission run IDs do not exactly match the frozen assignment")
        for template in templates:
            row = by_run.get(template["run_id"])
            if row is not None:
                validate_record(row, template, errors)
        reviewer_ids = sorted({x.get("form", {}).get("reviewer_id") for x in submission if x.get("form", {}).get("reviewer_id")})
        if len(reviewer_ids) != 1:
            errors.append("one assignment must have exactly one non-null human reviewer_id")
        result["reviewer_ids"] = reviewer_ids
        result["validated_reviews"] = len(submission)

        peers = [x.strip() for x in args.peer_reviewer_ids.split(",") if x.strip()]
        overlap = set(reviewer_ids) & set(peers)
        if overlap:
            errors.append("reviewer IDs must be distinct across independent repetitions: " + ", ".join(sorted(overlap)))
        result["peer_reviewer_ids"] = peers

    result["valid"] = not errors
    result["error_count"] = len(errors)
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
