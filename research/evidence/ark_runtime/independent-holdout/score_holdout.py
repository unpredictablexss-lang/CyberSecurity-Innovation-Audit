#!/usr/bin/env python3
"""Fail-closed root-cause score gate. Never scores development fixtures or predictions as truth."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from datetime import datetime, timezone


ROOT = Path(__file__).resolve().parent


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def git(repo, *args):
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True)
    if p.returncode:
        raise RuntimeError(p.stderr.decode("utf-8", "replace").strip())
    return p.stdout


def rows(path):
    with Path(path).open(encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def gate(args):
    freeze = json.loads(Path(args.freeze_record).read_text(encoding="utf-8"))
    detector_lock = json.loads(Path(args.detector_lock).read_text(encoding="utf-8"))
    manifest_path = Path(args.manifest)
    ledger_path = Path(args.ledger)
    predictions_path = Path(args.predictions)
    family_audit_path = Path(args.family_audit)
    exclusions_path = Path(args.exclusions)
    required_hashes = {
        "input_manifest_sha256": sha(manifest_path),
        "family_leakage_audit_sha256": sha(family_audit_path),
        "exclusion_ledger_sha256": sha(exclusions_path),
        "frozen_detector_sha256": sha(args.detector_lock),
        "adjudication_ledger_sha256": sha(ledger_path),
        "prediction_escrow_sha256": sha(predictions_path),
    }
    for field, actual in required_hashes.items():
        expected = freeze.get(field)
        if not expected or expected != actual:
            raise ValueError(field + " is missing or does not match the frozen artifact")
    for field in ("reviewer_1_submission_sha256", "reviewer_2_submission_sha256",
                  "reviewer_1_declaration_sha256", "reviewer_2_declaration_sha256"):
        if not freeze.get(field):
            raise ValueError("missing reviewer freeze evidence: " + field)
    for i in (1, 2):
        submission = Path(getattr(args, "reviewer" + str(i) + "_submission"))
        declaration_path = Path(getattr(args, "reviewer" + str(i) + "_declaration"))
        if sha(submission) != freeze["reviewer_" + str(i) + "_submission_sha256"]:
            raise ValueError("reviewer submission hash mismatch")
        if sha(declaration_path) != freeze["reviewer_" + str(i) + "_declaration_sha256"]:
            raise ValueError("reviewer declaration hash mismatch")
        declaration = json.loads(declaration_path.read_text(encoding="utf-8"))
        if declaration.get("participated_in_detector_or_rule_design_tuning") is not False:
            raise ValueError("reviewer is not independent of detector/rule tuning")
        if declaration.get("seen_predictions_or_tuning_results_for_these_cases") is not False:
            raise ValueError("reviewer saw predictions or tuning results")
        if declaration.get("can_label_independently_without_contact") is not True:
            raise ValueError("reviewer independence declaration is incomplete")
        if declaration.get("prior_public_source_or_patch_exposure") != "none":
            raise ValueError("reviewer reports source/patch exposure; replace or explicitly exclude")
        if declaration.get("signature_acknowledgement") != "I attest that these statements are accurate before receiving any case source materials.":
            raise ValueError("reviewer declaration lacks pre-access signature acknowledgement")
    manifest = rows(manifest_path)
    family_audit = rows(family_audit_path)
    manifest_family_ids = {r["family_id"] for r in manifest}
    audited_family_ids = {r.get("family_id", "") for r in family_audit}
    if (not family_audit or len(audited_family_ids) != len(family_audit)
            or audited_family_ids != manifest_family_ids
            or any(r.get("overlap_found", "").lower() not in {"yes", "no", "unknown"}
                   or r.get("scope_complete", "").lower() not in {"yes", "no"}
                   or not r.get("evidence_reference", "") for r in family_audit)):
        raise ValueError("root-cause family audit must cover every manifest family with evidence")
    exclusions = rows(exclusions_path)
    if (len({r["sample_id"] for r in exclusions}) != len(exclusions)
            or any(r["excluded"].lower() not in {"yes", "no"} for r in exclusions)):
        raise ValueError("exclusion ledger has duplicate samples or missing yes/no decisions")
    excluded_ids = {r["sample_id"] for r in exclusions if r["excluded"].lower() == "yes"}
    for r in exclusions:
        if r["excluded"].lower() == "yes" and not r["reason"].strip():
            raise ValueError("every excluded sample requires a reason")
    if freeze.get("prediction_reveal_after_label_freeze") is not True:
        raise ValueError("prediction escrow was not held until labels froze")
    if freeze.get("exclusion_reasons_recorded") is not True:
        raise ValueError("exclusion ledger is not complete")
    frozen_at = datetime.fromisoformat(freeze["labels_frozen_utc"].replace("Z", "+00:00"))
    if frozen_at.tzinfo is None or frozen_at > datetime.now(timezone.utc):
        raise ValueError("label freeze timestamp is invalid or in the future")
    revealed_at = datetime.fromisoformat(freeze["prediction_revealed_utc"].replace("Z", "+00:00"))
    if revealed_at.tzinfo is None or revealed_at <= frozen_at:
        raise ValueError("predictions were revealed before the adjudicated labels froze")

    ledger = rows(ledger_path)
    if not manifest or len({r["sample_id"] for r in manifest}) != len(manifest):
        raise ValueError("sample manifest is empty or has duplicate identities")
    by_id = {r["sample_id"]: r for r in manifest}
    if {r["sample_id"] for r in exclusions} != set(by_id):
        raise ValueError("exclusion ledger must record a yes/no decision for every sample")
    if not excluded_ids <= set(by_id):
        raise ValueError("exclusion ledger references an unknown sample")
    for family in family_audit:
        family_samples = set(filter(None, family["sample_ids_in_holdout"].split(";")))
        if not family_samples or any(s not in by_id or by_id[s].get("family_id") != family["family_id"] for s in family_samples):
            raise ValueError("family audit sample membership does not match frozen manifest")
        requires_exclusion = (family["overlap_found"].lower() in {"yes", "unknown"}
                              or family["scope_complete"].lower() != "yes")
        if requires_exclusion:
            if family["disposition"] != "excluded_entire_family" or not family_samples <= excluded_ids:
                raise ValueError("overlapping, unknown, or incompletely audited families must be excluded in full")
        elif family["disposition"] != "retained" and not family_samples <= excluded_ids:
            raise ValueError("family audit disposition requires reasoned sample exclusions")
    if set(r["path"] for r in manifest) & set(detector_lock["model_input_paths"]):
        raise ValueError("holdout paths overlap frozen detector model inputs")
    if len(ledger) != len(by_id) or {r["sample_id"] for r in ledger} != set(by_id):
        raise ValueError("adjudication ledger must account for every source row exactly once")
    id_key = rows(args.id_key)
    key_by_reviewer = {role: {r["case_id"]: r["sample_id"] for r in id_key if r["reviewer"] == role}
                       for role in ("reviewer_1", "reviewer_2")}
    reviewer_labels = {}
    for role, path in (("reviewer_1", args.reviewer1_submission), ("reviewer_2", args.reviewer2_submission)):
        submitted = rows(path)
        mapped = {}
        for r in submitted:
            sample_id = key_by_reviewer[role].get(r["case_id"])
            if sample_id is None or sample_id in mapped or r["label"] not in {"vulnerable", "fixed", "safe", "unrelated", "unknown"}:
                raise ValueError(role + " submission has an invalid or duplicate case")
            mapped[sample_id] = r["label"]
        if set(mapped) != set(by_id):
            raise ValueError(role + " did not independently label every sample exactly once")
        reviewer_labels[role] = mapped

    # Re-derive source identities from the pinned Git object store. Any mismatch blocks the whole score.
    for row in manifest:
        tree = git(args.runtime_repo, "rev-parse", "--verify", row["commit"] + "^{tree}").decode().strip()
        blob = git(args.runtime_repo, "rev-parse", "--verify", row["commit"] + ":" + row["path"]).decode().strip()
        content = git(args.runtime_repo, "cat-file", "blob", row["commit"] + ":" + row["path"])
        if (tree != row["tree"] or blob != row["blob"] or sha_bytes(content) != row["source_sha256"]):
            raise ValueError("source identity mismatch; refusing metrics: " + row["sample_id"])

    prediction_doc = json.loads(predictions_path.read_text(encoding="utf-8"))
    if prediction_doc.get("manifest_sha256") != sha(manifest_path):
        raise ValueError("prediction escrow is not bound to the frozen input manifest")
    predictions = {c["sample_id"]: c for c in prediction_doc.get("cases", [])}
    if set(predictions) != set(by_id):
        raise ValueError("prediction escrow does not contain the exact frozen sample identities")
    ledger_by_id = {r["sample_id"]: r for r in ledger}

    totals = {"tp": 0, "fp": 0, "fn": 0}
    counts = {"samples": len(manifest), "scored_samples": 0,
              "parser_complete": sum(r["parse_status"] == "complete" for r in manifest),
              "partial": sum(r["parse_status"] != "complete" for r in manifest),
              "unknown": sum(r["adjudicated_label"] == "unknown" for r in ledger),
              "excluded": 0, "not_applicable": 0, "blocked_or_failed": 0}
    required_classes = {"vulnerable", "fixed", "safe", "unrelated"}
    retained_labels = {ledger_by_id[s]["adjudicated_label"] for s in by_id if s not in excluded_ids}
    missing_classes = required_classes - retained_labels
    retained_partial = [r for r in manifest if r["sample_id"] not in excluded_ids and r["parse_status"] != "complete"]
    if missing_classes:
        raise ValueError("required adjudicated class coverage missing: " + ", ".join(sorted(missing_classes)))
    if not retained_partial:
        raise ValueError("holdout must retain at least one parser-incomplete source unit")
    counts["partial_retained"] = len(retained_partial)
    counts["unknown_retained"] = sum(ledger_by_id[s]["adjudicated_label"] == "unknown"
                                     for s in by_id if s not in excluded_ids)
    seen_pairs = set()
    for sample_id, row in by_id.items():
        label = ledger_by_id[sample_id]
        pred = predictions[sample_id]
        if label["source_sha256"] != row["source_sha256"] or label["identity_verified"].lower() != "true":
            raise ValueError("ledger source identity is not verified for " + sample_id)
        allowed = {"vulnerable", "fixed", "safe", "unrelated", "unknown"}
        if label["reviewer_1_label"] not in allowed or label["reviewer_2_label"] not in allowed:
            raise ValueError("both independent labels are required for " + sample_id)
        if (reviewer_labels["reviewer_1"][sample_id] != label["reviewer_1_label"]
                or reviewer_labels["reviewer_2"][sample_id] != label["reviewer_2_label"]):
            raise ValueError("adjudication ledger does not match frozen reviewer labels for " + sample_id)
        if pred.get("source_sha256") != row["source_sha256"]:
            raise ValueError("prediction source identity mismatch for " + sample_id)
        if sample_id in excluded_ids:
            counts["excluded"] += 1
            continue
        if label["parser_status"] != row["parse_status"]:
            raise ValueError("adjudicated parser status differs from frozen manifest for " + sample_id)
        parser_status = row["parse_status"]
        truth_label = label["adjudicated_label"]
        if parser_status != "complete":
            continue
        if truth_label == "unknown":
            continue
        if truth_label not in {"vulnerable", "fixed", "safe", "unrelated"}:
            raise ValueError("missing/invalid adjudicated label for " + sample_id)
        if pred.get("coverage_status") == "not_applicable":
            counts["not_applicable"] += 1
            raise ValueError("detector did not cover sample; no metrics can be computed")
        if pred.get("execution_status") != "completed" or pred.get("coverage_status") != "applicable":
            counts["blocked_or_failed"] += 1
            raise ValueError("incomplete detector execution; no metrics can be computed")
        truth = set(filter(None, label["ground_truth_root_cause_ids"].split(";")))
        predicted = set(filter(None, pred.get("predicted_root_cause_ids", [])))
        if truth_label == "vulnerable" and not truth:
            raise ValueError("vulnerable row lacks adjudicated root-cause identity: " + sample_id)
        if truth_label != "vulnerable" and truth:
            raise ValueError("non-vulnerable row has active ground-truth causes: " + sample_id)
        for cause in truth | predicted:
            pair = (sample_id, cause)
            if pair in seen_pairs:
                continue
            seen_pairs.add(pair)
            if cause in truth and cause in predicted: totals["tp"] += 1
            elif cause in predicted: totals["fp"] += 1
            elif cause in truth: totals["fn"] += 1
        counts["scored_samples"] += 1

    if counts["scored_samples"] == 0:
        raise ValueError("no eligible, applicable, complete, independently adjudicated samples")
    precision = totals["tp"] / (totals["tp"] + totals["fp"]) if totals["tp"] + totals["fp"] else None
    recall = totals["tp"] / (totals["tp"] + totals["fn"]) if totals["tp"] + totals["fn"] else None
    return {"assessment_id": freeze["assessment_id"], "status": "scored_with_limitations",
            "sample_counts": counts, "root_cause_counts": totals,
            "precision": precision, "recall": recall,
            "formula": "deduplicated (sample_id, adjudicated root-cause ID); unknown, partial, excluded, blocked, and not-applicable are not negatives",
            "limitations": ["Purposive sample; no population-level inference.",
                            "Patch families must remain wholly in holdout and be absent from all development/tuning material."]}


def sha_bytes(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--runtime-repo", required=True)
    ap.add_argument("--manifest", default=str(ROOT / "admin" / "holdout_source_manifest.csv"))
    ap.add_argument("--detector-lock", default=str(ROOT / "admin" / "frozen_detector.json"))
    ap.add_argument("--freeze-record", required=True)
    ap.add_argument("--reviewer1-submission", required=True)
    ap.add_argument("--reviewer2-submission", required=True)
    ap.add_argument("--reviewer1-declaration", required=True)
    ap.add_argument("--reviewer2-declaration", required=True)
    ap.add_argument("--ledger", required=True)
    ap.add_argument("--family-audit", required=True)
    ap.add_argument("--exclusions", required=True)
    ap.add_argument("--id-key", default=str(ROOT / "admin" / "reviewer_id_key.csv"))
    ap.add_argument("--predictions", required=True, help="Admin escrow JSON; never pass to reviewers")
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    try:
        result = gate(args)
    except Exception as exc:
        print(json.dumps({"status": "not_estimable", "metrics": None,
                          "reason": str(exc)}, ensure_ascii=False))
        return 2
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "root_cause_counts": result["root_cause_counts"],
                      "precision": result["precision"], "recall": result["recall"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

