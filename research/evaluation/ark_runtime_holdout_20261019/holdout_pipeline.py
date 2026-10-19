#!/usr/bin/env python3
"""C13 independent holdout freeze, double-blind review and metric gate."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

PROTOCOL_SCHEMA = "ohscanner.ark-holdout-real-input-protocol/v1"
FREEZE_SCHEMA = "ohscanner.ark-holdout-freeze/v2"
INTAKE_SCHEMA = "ohscanner.ark-holdout-intake/v2"
TRUTH_SCHEMA = "ohscanner.ark-holdout-truth/v2"
REVIEW_SCHEMA = "ohscanner.ark-holdout-review/v2"
LOCK_SCHEMA = "ohscanner.ark-holdout-review-lock/v2"
ADJUDICATION_SCHEMA = "ohscanner.ark-holdout-adjudication/v2"
ADJUDICATION_SUBMISSION_SCHEMA = "ohscanner.ark-holdout-adjudication-submission/v2"
FINAL_SCHEMA = "ohscanner.ark-holdout-final-labels/v2"
COMMITMENT_SCHEMA = "ohscanner.ark-holdout-truth-commitment/v2"
SCORE_SCHEMA = "ohscanner.ark-holdout-score/v2"
LEDGER_SCHEMA = "ohscanner.ark-holdout-development-leakage-ledger/v1"
ALLOWED_LABELS = {"vulnerable_shape", "not_vulnerable_shape", "unknown"}
REQUIRED_CASE_IDENTITY = {
    "repository", "commit", "tree", "blob", "source_sha256",
    "source_path", "parser_identity", "snapshot_sha256",
}
REVIEWER_ATTESTATIONS = (
    "truth_not_seen", "other_review_not_seen", "scanner_outputs_not_seen",
    "model_outputs_not_seen", "parent_fixed_pairing_not_seen", "independent_review",
)
ADJUDICATOR_ATTESTATIONS = (
    "truth_not_seen", "scanner_outputs_not_seen", "model_outputs_not_seen",
    "parent_fixed_pairing_not_seen", "independent_adjudication",
)


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha256(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def payload_hash(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


def verify_payload_hash(value: dict[str, Any], expected_key: str = "payload_sha256") -> bool:
    if not isinstance(value, dict) or expected_key not in value:
        return False
    body = dict(value)
    expected = body.pop(expected_key)
    return isinstance(expected, str) and hmac.compare_digest(expected, payload_hash(body))


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")


def safe_relative(value: str) -> bool:
    p = PurePosixPath(value)
    return bool(value) and not p.is_absolute() and ".." not in p.parts and "\\" not in value


def source_leak_errors(data: bytes, case_id: str, source_path: str) -> list[str]:
    text = data.decode("utf-8", errors="replace")
    forbidden = {
        "case_id_in_source": case_id in text,
        "source_path_in_source": source_path in text,
        "url_in_source": bool(re.search(r"https?://", text, re.IGNORECASE)),
        "cve_identifier_in_source": bool(re.search(r"CVE-\d{4}-\d+", text, re.IGNORECASE)),
        "issue_or_pull_reference_in_source": bool(re.search(r"(issues?/\d+|pulls?/\d+|![0-9]{3,})", text, re.IGNORECASE)),
        "scanner_rule_id_in_source": bool(re.search(r"(ohscanner|detector|rule[_ -]?id|scanner verdict)", text, re.IGNORECASE)),
    }
    return ["source_metadata_leak:" + key for key, present in forbidden.items() if present]


def pseudonym(secret: bytes, case_id: str) -> str:
    return hmac.new(secret, case_id.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def truth_commitment(secret: bytes, truth: dict[str, Any]) -> str:
    body = {
        "schema": truth.get("schema"),
        "execution_mode": truth.get("execution_mode"),
        "truth_status": truth.get("truth_status"),
        "model_generated": truth.get("model_generated"),
        "labels": truth.get("labels"),
    }
    return hmac.new(secret, canonical_json_bytes(body), hashlib.sha256).hexdigest()


def validate_protocol(protocol: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if protocol.get("schema") != PROTOCOL_SCHEMA:
        errors.append("protocol_schema")
    if protocol.get("status") != "FROZEN_NOT_EXECUTED":
        errors.append("protocol_not_frozen")
    if protocol.get("execution_mode") not in {"real_holdout", "pipeline_self_test"}:
        errors.append("protocol_execution_mode")
    if protocol.get("sampling_frame", {}).get("required_case_identity") != sorted(REQUIRED_CASE_IDENTITY):
        errors.append("protocol_required_case_identity")
    review = protocol.get("double_blind_review", {})
    if review.get("reviewer_count") != 2 or review.get("adjudicator_count") != 1:
        errors.append("protocol_reviewer_counts")
    if review.get("allowed_labels") != sorted(ALLOWED_LABELS):
        errors.append("protocol_label_set")
    if not review.get("reviewer_attestations") or not review.get("adjudicator_attestations"):
        errors.append("protocol_attestations")
    required = {
        "protocol_file_hash_verified", "truth_commitment_verified",
        "truth_status_reliable_independent_human_adjudicated", "model_generated_false",
        "development_overlap_false", "reviewer_independence_attested",
        "adjudication_complete", "source_identity_complete", "case_set_exact",
        "no_unknown_labels",
    }
    if set(protocol.get("metric_gate", {}).get("required_conditions", [])) != required:
        errors.append("protocol_metric_gate")
    if protocol.get("secret_handling", {}).get("commit_secrets_to_git") is not False:
        errors.append("protocol_secret_handling")
    return errors


def validate_development_leakage_ledger(
    ledger: dict[str, Any], ledger_file_hash: str, intake: dict[str, Any],
    protocol_file_hash: str,
) -> list[str]:
    errors: list[str] = []
    if ledger.get("schema") != LEDGER_SCHEMA:
        errors.append("development_leakage_ledger_schema")
    if ledger.get("status") != "COMPLETE_LOCAL_DEVELOPMENT_ARTIFACTS":
        errors.append("development_leakage_ledger_not_complete")
    if not verify_payload_hash(ledger):
        errors.append("development_leakage_ledger_payload_hash")
    if ledger.get("protocol_file_sha256") != protocol_file_hash:
        errors.append("development_leakage_ledger_protocol_hash")
    if intake.get("development_leakage_ledger_sha256") != ledger_file_hash:
        errors.append("development_leakage_ledger_file_hash")
    if intake.get("development_leakage_ledger_payload_sha256") != ledger.get("payload_sha256"):
        errors.append("development_leakage_ledger_intake_payload_hash")
    excluded_ids = ledger.get("excluded_case_ids", [])
    excluded_hashes = ledger.get("excluded_source_sha256", [])
    rows = ledger.get("excluded_sources", [])
    if excluded_ids != sorted(set(excluded_ids)):
        errors.append("development_leakage_ledger_case_ids_not_canonical")
    if excluded_hashes != sorted({row.get("sha256") for row in rows}):
        errors.append("development_leakage_ledger_source_hashes_not_canonical")
    case_ids = {case.get("case_id") for case in intake.get("cases", [])}
    source_hashes = {case.get("source_sha256") for case in intake.get("cases", [])}
    if case_ids & set(excluded_ids):
        errors.append("development_case_id_overlap")
    if source_hashes & set(excluded_hashes):
        errors.append("development_source_hash_overlap")
    if any(case.get("sampling_frame_sha256") != ledger.get("selection_frame_sha256") for case in intake.get("cases", [])):
        errors.append("development_ledger_selection_frame_mismatch")
    return errors


def validate_intake(
    intake: dict[str, Any], truth: dict[str, Any], source_root: Path,
    protocol: dict[str, Any], protocol_file_hash: str,
    development_leakage_ledger: dict[str, Any], development_leakage_ledger_file_hash: str,
) -> list[str]:
    errors = validate_protocol(protocol)
    errors.extend(validate_development_leakage_ledger(
        development_leakage_ledger, development_leakage_ledger_file_hash, intake, protocol_file_hash
    ))
    if intake.get("schema") != INTAKE_SCHEMA:
        errors.append("intake_schema")
    if truth.get("schema") != TRUTH_SCHEMA:
        errors.append("truth_schema")
    execution_mode = protocol.get("execution_mode")
    if intake.get("execution_mode") != execution_mode:
        errors.append("intake_execution_mode")
    if truth.get("execution_mode") != execution_mode:
        errors.append("truth_execution_mode")
    if intake.get("protocol_file_sha256") != protocol_file_hash:
        errors.append("intake_protocol_hash")
    for key in ("preregistration_sha256", "development_leakage_ledger_sha256", "family_split_sha256"):
        if not intake.get(key):
            errors.append("missing_" + key)
    if not isinstance(intake.get("sample_size"), int) or intake.get("sample_size", 0) <= 0:
        errors.append("invalid_sample_size")
    expected_truth_status = (
        "reliable_independent_human_adjudicated"
        if execution_mode == "real_holdout"
        else "pipeline_self_test_not_reliable"
    )
    if truth.get("truth_status") != expected_truth_status:
        errors.append("truth_status_not_expected")
    for key in ("model_generated", "scanner_outputs_used", "development_artifacts_used", "model_outputs_used"):
        if truth.get(key) is not False:
            errors.append("truth_" + key)
    cases = intake.get("cases", [])
    labels = truth.get("labels", {})
    ids = [case.get("case_id") for case in cases]
    if len(ids) != len(set(ids)):
        errors.append("duplicate_case_id")
    if set(ids) != set(labels):
        errors.append("truth_case_set_mismatch")
    if intake.get("sample_size") != len(cases):
        errors.append("sample_size_case_count_mismatch")
    for case in cases:
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            errors.append("empty_case_id")
            continue
        if REQUIRED_CASE_IDENTITY - set(case):
            errors.append(f"incomplete_source_identity:{case_id}")
        if case.get("development_overlap") is not False:
            errors.append(f"development_overlap_not_false:{case_id}")
        if case.get("development_leakage_match") is not False:
            errors.append(f"development_leakage_match:{case_id}")
        if not case.get("selection_rule_id") or not case.get("sampling_frame_sha256"):
            errors.append(f"missing_selection_binding:{case_id}")
        if not case.get("family_id") or not case.get("family_split"):
            errors.append(f"missing_family_split:{case_id}")
        source_path = case.get("source_path", "")
        if not safe_relative(source_path):
            errors.append(f"unsafe_source_path:{case_id}")
            continue
        path = source_root.joinpath(*PurePosixPath(source_path).parts)
        try:
            data = path.read_bytes()
        except OSError:
            errors.append(f"missing_source:{case_id}")
            continue
        errors.extend(source_leak_errors(data, case_id, source_path))
        if case.get("source_sha256") != sha256_bytes(data):
            errors.append(f"source_sha256_mismatch:{case_id}")
        if not all(isinstance(case.get(key), str) and case.get(key) for key in ("repository", "commit", "tree", "blob", "parser_identity", "snapshot_sha256")):
            errors.append(f"invalid_source_identity_binding:{case_id}")
        entry = labels.get(case_id, {})
        if entry.get("label") not in ALLOWED_LABELS:
            errors.append(f"invalid_truth_label:{case_id}")
        if entry.get("model_generated") is not False:
            errors.append(f"truth_label_model_generated:{case_id}")
    return errors

def freeze(args: argparse.Namespace) -> int:
    intake = load_json(args.cases)
    truth = load_json(args.truth)
    protocol = load_json(args.protocol)
    development_leakage_ledger = load_json(args.development_leakage_ledger)
    source_root = args.source_root.resolve()
    protocol_file_hash = file_sha256(args.protocol)
    development_leakage_ledger_file_hash = file_sha256(args.development_leakage_ledger)
    errors = validate_intake(
        intake, truth, source_root, protocol, protocol_file_hash,
        development_leakage_ledger, development_leakage_ledger_file_hash,
    )
    if errors:
        raise SystemExit("freeze rejected: " + ", ".join(errors))
    secret = args.secret_file.read_bytes().strip()
    if not secret:
        raise SystemExit("empty custodian secret")
    rows = []
    packets = {}
    for case in intake["cases"]:
        case_id = case["case_id"]
        data = source_root.joinpath(*PurePosixPath(case["source_path"]).parts).read_bytes()
        source_hash = sha256_bytes(data)
        pseudo = pseudonym(secret, case_id)
        rows.append({
            "case_pseudonym": pseudo,
            "case_commitment_sha256": payload_hash({"case_id": case_id, "source_sha256": source_hash}),
            "source_sha256": source_hash,
            "source_bytes": len(data),
            "repository": case["repository"], "commit": case["commit"],
            "tree": case["tree"], "blob": case["blob"],
            "parser_identity": case["parser_identity"], "snapshot_sha256": case["snapshot_sha256"],
            "selection_rule_id": case["selection_rule_id"],
            "sampling_frame_sha256": case["sampling_frame_sha256"],
            "family_id": case["family_id"], "family_split": case["family_split"],
            "development_overlap": False, "development_leakage_match": False,
        })
        packets[pseudo] = {
            "case_pseudonym": pseudo,
            "source_text": data.decode("utf-8", errors="replace"),
            "task": "Classify only the source shape. Do not infer product exploitability.",
            "allowed_labels": sorted(ALLOWED_LABELS),
            "forbidden_context": [
                "true label", "case id", "source path", "repository or commit identity",
                "source hash", "parent/fixed pairing", "scanner verdict", "model output",
            ],
            "submission_requirements": {
                "fields": ["case_pseudonym", "label", "confidence", "rationale", "evidence"],
                "evidence": "Non-empty bounded source locations or quoted code facts.",
            },
        }
    rows.sort(key=lambda item: item["case_pseudonym"])
    reviewer_attestation = {name: True for name in REVIEWER_ATTESTATIONS}
    packet_a = {
        "schema": REVIEW_SCHEMA, "packet_role": "reviewer", "reviewer_id": "A",
        "blindness_contract": protocol["double_blind_review"],
        "attestation_required": reviewer_attestation,
        "cases": [packets[row["case_pseudonym"]] for row in rows],
    }
    packet_b = {
        "schema": REVIEW_SCHEMA, "packet_role": "reviewer", "reviewer_id": "B",
        "blindness_contract": protocol["double_blind_review"],
        "attestation_required": reviewer_attestation,
        "cases": [packets[row["case_pseudonym"]] for row in reversed(rows)],
    }
    commitment = truth_commitment(secret, truth)
    manifest = {
        "schema": FREEZE_SCHEMA,
        "status": "FROZEN_PIPELINE_ONLY" if protocol["execution_mode"] == "pipeline_self_test" else "FROZEN_REAL_INPUTS",
        "execution_mode": protocol["execution_mode"],
        "protocol_file_sha256": protocol_file_hash,
        "development_leakage_ledger_file_sha256": development_leakage_ledger_file_hash,
        "development_leakage_ledger_payload_sha256": development_leakage_ledger.get("payload_sha256"),
        "truth_status": truth.get("truth_status"),
        "truth_commitment_scheme": "hmac-sha256-custodian-secret-v1",
        "truth_commitment_sha256": commitment,
        "case_count": len(rows),
        "case_pseudonyms": [row["case_pseudonym"] for row in rows],
        "public_case_rows": rows,
        "review_protocol": protocol["double_blind_review"],
        "metric_gate": protocol["metric_gate"],
        "packet_payload_sha256": {"A": payload_hash(packet_a), "B": payload_hash(packet_b)},
    }
    manifest["payload_sha256"] = payload_hash(manifest)
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "freeze_manifest.json", manifest)
    write_json(out / "reviewer_packet_A.json", packet_a)
    write_json(out / "reviewer_packet_B.json", packet_b)
    write_json(out / "truth_commitment.json", {
        "schema": COMMITMENT_SCHEMA,
        "scheme": "hmac-sha256-custodian-secret-v1",
        "commitment_sha256": commitment,
        "protocol_file_sha256": protocol_file_hash,
        "development_leakage_ledger_file_sha256": development_leakage_ledger_file_hash,
        "development_leakage_ledger_payload_sha256": development_leakage_ledger.get("payload_sha256"),
        "truth_status": truth.get("truth_status"),
        "secret_not_published": True,
    })
    write_json(out / "adjudication_template.json", {
        "schema": ADJUDICATION_SUBMISSION_SCHEMA,
        "freeze_payload_sha256": manifest["payload_sha256"],
        "decisions": [], "required_fields": ["case_pseudonym", "decision", "rationale", "evidence"],
        "attestation_required": {name: True for name in ADJUDICATOR_ATTESTATIONS},
    })
    print(json.dumps({"status": manifest["status"], "case_count": len(rows), "truth_status": manifest["truth_status"]}, indent=2))
    return 0


def validate_submission(freeze_manifest: dict[str, Any], packet: dict[str, Any], submission: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if submission.get("schema") != REVIEW_SCHEMA:
        errors.append("submission_schema")
    if submission.get("packet_sha256") != payload_hash(packet):
        errors.append("packet_hash_mismatch")
    if submission.get("reviewer_id") != packet.get("reviewer_id"):
        errors.append("reviewer_id_mismatch")
    attestations = submission.get("independence_attestations", {})
    for name in REVIEWER_ATTESTATIONS:
        if attestations.get(name) is not True:
            errors.append(f"missing_attestation:{name}")
    expected = set(freeze_manifest["case_pseudonyms"])
    rows = submission.get("labels", [])
    seen = set()
    for row in rows:
        pseudo = row.get("case_pseudonym")
        if pseudo not in expected or pseudo in seen:
            errors.append(f"bad_or_duplicate_case:{pseudo}")
            continue
        seen.add(pseudo)
        if row.get("label") not in ALLOWED_LABELS:
            errors.append(f"bad_label:{pseudo}")
        if row.get("confidence") not in {"high", "medium", "low"}:
            errors.append(f"bad_confidence:{pseudo}")
        if not isinstance(row.get("rationale"), str) or len(row.get("rationale", "").strip()) < 20:
            errors.append(f"insufficient_rationale:{pseudo}")
        if not isinstance(row.get("evidence"), list) or not row.get("evidence"):
            errors.append(f"missing_evidence:{pseudo}")
    if seen != expected:
        errors.append("submission_case_set_mismatch")
    return errors


def lock_review(args: argparse.Namespace) -> int:
    freeze_manifest = load_json(args.freeze_manifest)
    packet = load_json(args.packet)
    submission = load_json(args.submission)
    errors = validate_submission(freeze_manifest, packet, submission)
    if errors:
        raise SystemExit("review rejected: " + ", ".join(errors))
    lock = {
        "schema": LOCK_SCHEMA, "reviewer_id": packet["reviewer_id"],
        "freeze_payload_sha256": freeze_manifest["payload_sha256"],
        "packet_payload_sha256": payload_hash(packet),
        "submission_payload_sha256": payload_hash(submission),
        "independence_attestations": submission["independence_attestations"],
        "labels": sorted(submission["labels"], key=lambda item: item["case_pseudonym"]),
    }
    lock["payload_sha256"] = payload_hash(lock)
    write_json(args.output, lock)
    print(json.dumps({"status": "LOCKED", "reviewer": lock["reviewer_id"], "payload_sha256": lock["payload_sha256"]}, indent=2))
    return 0


def validate_lock(lock: dict[str, Any], expected_reviewer: str, expected_freeze_hash: str) -> list[str]:
    errors = []
    if lock.get("schema") != LOCK_SCHEMA:
        errors.append(f"lock_schema:{expected_reviewer}")
    if not verify_payload_hash(lock):
        errors.append(f"lock_payload_hash:{expected_reviewer}")
    if lock.get("reviewer_id") != expected_reviewer:
        errors.append(f"lock_reviewer:{expected_reviewer}")
    if lock.get("freeze_payload_sha256") != expected_freeze_hash:
        errors.append(f"lock_freeze_hash:{expected_reviewer}")
    for name in REVIEWER_ATTESTATIONS:
        if lock.get("independence_attestations", {}).get(name) is not True:
            errors.append(f"lock_attestation:{expected_reviewer}:{name}")
    return errors


def adjudicate(args: argparse.Namespace) -> int:
    a = load_json(args.review_a)
    b = load_json(args.review_b)
    errors = validate_lock(a, "A", a.get("freeze_payload_sha256", "")) + validate_lock(b, "B", a.get("freeze_payload_sha256", ""))
    if a.get("freeze_payload_sha256") != b.get("freeze_payload_sha256"):
        errors.append("review_freeze_mismatch")
    a_rows = {row["case_pseudonym"]: row for row in a.get("labels", [])}
    b_rows = {row["case_pseudonym"]: row for row in b.get("labels", [])}
    if set(a_rows) != set(b_rows):
        errors.append("review_case_set_mismatch")
    if errors:
        raise SystemExit("adjudication rejected: " + ", ".join(errors))
    agreements = []
    disagreements = []
    for pseudo in sorted(a_rows):
        left, right = a_rows[pseudo], b_rows[pseudo]
        if left["label"] == right["label"]:
            agreements.append({"case_pseudonym": pseudo, "label": left["label"], "route": "agreement"})
        else:
            disagreements.append({
                "case_pseudonym": pseudo, "reviewer_1_label": left["label"], "reviewer_2_label": right["label"],
                "reviewer_1_rationale": left["rationale"], "reviewer_2_rationale": right["rationale"],
                "reviewer_1_evidence": left["evidence"], "reviewer_2_evidence": right["evidence"],
            })
    out = {
        "schema": ADJUDICATION_SCHEMA,
        "freeze_payload_sha256": a["freeze_payload_sha256"],
        "status": "THIRD_REVIEW_REQUIRED" if disagreements else "AGREEMENT_COMPLETE",
        "adjudicator_independence_required": {name: True for name in ADJUDICATOR_ATTESTATIONS},
        "agreements": agreements, "disagreements": disagreements,
    }
    out["payload_sha256"] = payload_hash(out)
    write_json(args.output, out)
    print(json.dumps({"status": out["status"], "agreements": len(agreements), "disagreements": len(disagreements)}, indent=2))
    return 0


def apply_adjudication(args: argparse.Namespace) -> int:
    packet = load_json(args.adjudication_packet)
    submission = load_json(args.adjudication_submission)
    errors = []
    if packet.get("schema") != ADJUDICATION_SCHEMA or not verify_payload_hash(packet):
        errors.append("adjudication_packet_payload")
    if submission.get("schema") != ADJUDICATION_SUBMISSION_SCHEMA:
        errors.append("adjudication_submission_schema")
    if submission.get("freeze_payload_sha256") != packet.get("freeze_payload_sha256"):
        errors.append("adjudication_freeze_mismatch")
    attestations = submission.get("independence_attestations", {})
    for name in ADJUDICATOR_ATTESTATIONS:
        if attestations.get(name) is not True:
            errors.append(f"adjudicator_attestation:{name}")
    disagreement_rows = {row["case_pseudonym"]: row for row in packet.get("disagreements", [])}
    expected = set(disagreement_rows)
    decisions = {row.get("case_pseudonym"): row for row in submission.get("decisions", [])}
    if set(decisions) != expected:
        errors.append("adjudication_decision_set_mismatch")
    for pseudo in expected:
        decision = decisions.get(pseudo, {})
        if decision.get("decision") not in ALLOWED_LABELS:
            errors.append(f"bad_adjudication_decision:{pseudo}")
        review_labels = {
            disagreement_rows[pseudo].get("reviewer_1_label"),
            disagreement_rows[pseudo].get("reviewer_2_label"),
        }
        if "unknown" in review_labels and decision.get("decision") != "unknown":
            errors.append(f"unknown_not_preserved:{pseudo}")
        if not isinstance(decision.get("rationale"), str) or len(decision.get("rationale", "").strip()) < 20:
            errors.append(f"insufficient_adjudication_rationale:{pseudo}")
        if not isinstance(decision.get("evidence"), list) or not decision.get("evidence"):
            errors.append(f"missing_adjudication_evidence:{pseudo}")
    if errors:
        raise SystemExit("adjudication application rejected: " + ", ".join(errors))
    final_rows = []
    for row in packet.get("agreements", []):
        final_rows.append({"case_pseudonym": row["case_pseudonym"], "label": row["label"], "route": "agreement"})
    for row in packet.get("disagreements", []):
        decision = decisions[row["case_pseudonym"]]
        final_rows.append({"case_pseudonym": row["case_pseudonym"], "label": decision["decision"], "route": "third_review_adjudication"})
    out = {
        "schema": FINAL_SCHEMA, "freeze_payload_sha256": packet.get("freeze_payload_sha256"),
        "status": "FINAL_LABELS_AVAILABLE", "labels": sorted(final_rows, key=lambda item: item["case_pseudonym"]),
        "model_generated": False, "truth_reveal_allowed": False,
    }
    out["payload_sha256"] = payload_hash(out)
    write_json(args.output, out)
    print(json.dumps({"status": out["status"], "label_count": len(final_rows)}, indent=2))
    return 0


def score(args: argparse.Namespace) -> int:
    truth = load_json(args.truth)
    final = load_json(args.final_labels)
    manifest = load_json(args.freeze_manifest)
    protocol = load_json(args.protocol)
    intake = load_json(args.cases)
    development_leakage_ledger = load_json(args.development_leakage_ledger)
    protocol_file_hash = file_sha256(args.protocol)
    development_leakage_ledger_file_hash = file_sha256(args.development_leakage_ledger)
    secret = args.secret_file.read_bytes().strip()
    errors = validate_protocol(protocol)
    if truth.get("truth_status") != "reliable_independent_human_adjudicated" or truth.get("model_generated") is not False:
        out = {
            "schema": SCORE_SCHEMA,
            "status": "NOT_RUN",
            "reason": "truth is not reliable independent human adjudicated",
            "precision": None,
            "recall": None,
            "f1": None,
        }
        write_json(args.output, out)
        print(json.dumps(out, indent=2))
        return 3
    if not secret:
        errors.append("empty_custodian_secret")
    if manifest.get("protocol_file_sha256") != protocol_file_hash:
        errors.append("protocol_file_hash_mismatch")
    errors.extend(validate_development_leakage_ledger(
        development_leakage_ledger, development_leakage_ledger_file_hash, intake, protocol_file_hash
    ))
    if manifest.get("development_leakage_ledger_file_sha256") != development_leakage_ledger_file_hash:
        errors.append("development_leakage_ledger_manifest_file_hash")
    if manifest.get("development_leakage_ledger_payload_sha256") != development_leakage_ledger.get("payload_sha256"):
        errors.append("development_leakage_ledger_manifest_payload_hash")
    if manifest.get("truth_status") != truth.get("truth_status"):
        errors.append("truth_status_manifest_mismatch")
    if not verify_payload_hash(manifest):
        errors.append("freeze_manifest_payload_hash")
    if not verify_payload_hash(final):
        errors.append("final_labels_payload_hash")
    if final.get("freeze_payload_sha256") != manifest.get("payload_sha256"):
        errors.append("final_freeze_hash_mismatch")
    if final.get("model_generated") is not False:
        errors.append("final_model_generated")
    labels_by_pseudo: dict[str, Any] = {}
    if secret:
        if not hmac.compare_digest(truth_commitment(secret, truth), manifest.get("truth_commitment_sha256", "")):
            errors.append("truth_commitment_mismatch")
        labels_by_pseudo = {pseudonym(secret, case_id): row for case_id, row in truth.get("labels", {}).items()}
    predicted = {row.get("case_pseudonym"): row for row in final.get("labels", [])}
    if set(labels_by_pseudo) != set(predicted):
        errors.append("truth_final_case_set_mismatch")
    if set(manifest.get("case_pseudonyms", [])) != set(predicted):
        errors.append("manifest_final_case_set_mismatch")
    for row in predicted.values():
        if row.get("label") not in ALLOWED_LABELS:
            errors.append("final_invalid_label")

    matrix = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "unknown": 0}
    for pseudo, truth_row in labels_by_pseudo.items():
        pred = predicted.get(pseudo, {}).get("label", "unknown")
        true = truth_row.get("label", "unknown")
        if pred == "unknown" or true == "unknown":
            matrix["unknown"] += 1
        elif true == "vulnerable_shape" and pred == "vulnerable_shape":
            matrix["TP"] += 1
        elif true == "not_vulnerable_shape" and pred == "vulnerable_shape":
            matrix["FP"] += 1
        elif true == "vulnerable_shape" and pred == "not_vulnerable_shape":
            matrix["FN"] += 1
        else:
            matrix["TN"] += 1

    complete_identity = all(
        REQUIRED_CASE_IDENTITY <= set(case)
        and case.get("development_overlap") is False
        and case.get("development_leakage_match") is False
        for case in intake.get("cases", [])
    )
    gate_state = {
        "protocol_file_hash_verified": manifest.get("protocol_file_sha256") == protocol_file_hash,
        "truth_commitment_verified": "truth_commitment_mismatch" not in errors,
        "truth_status_reliable_independent_human_adjudicated": truth.get("truth_status") == "reliable_independent_human_adjudicated",
        "model_generated_false": truth.get("model_generated") is False and final.get("model_generated") is False,
        "development_overlap_false": complete_identity,
        "reviewer_independence_attested": manifest.get("review_protocol", {}).get("reviewer_independence_required") is True,
        "adjudication_complete": final.get("status") == "FINAL_LABELS_AVAILABLE",
        "source_identity_complete": complete_identity,
        "case_set_exact": set(labels_by_pseudo) == set(predicted) == set(manifest.get("case_pseudonyms", [])),
        "no_unknown_labels": matrix["unknown"] == 0,
    }
    required_conditions = set(protocol.get("metric_gate", {}).get("required_conditions", []))
    gate_errors = [name for name in sorted(required_conditions) if not gate_state.get(name)]
    if errors:
        status, exit_code = "REJECTED", 2
    elif gate_errors:
        status, exit_code = "PARTIAL_NOT_METRIC_ELIGIBLE", 4
    else:
        status, exit_code = "COMPLETE", 0
    out: dict[str, Any] = {
        "schema": SCORE_SCHEMA, "status": status, "confusion_matrix": matrix,
        "metric_gate": gate_state, "metric_gate_failures": gate_errors,
        "validation_errors": errors, "precision": None, "recall": None, "f1": None,
    }
    if status == "COMPLETE":
        tp, fp, fn = matrix["TP"], matrix["FP"], matrix["FN"]
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        out.update({
            "precision": precision, "recall": recall,
            "f1": (2 * precision * recall / (precision + recall)) if precision + recall else 0.0,
        })
    write_json(args.output, out)
    print(json.dumps(out, indent=2))
    return exit_code


def self_test(args: argparse.Namespace) -> int:
    work = args.work_dir.resolve()
    evaluation_root = Path(__file__).resolve().parent
    if work == evaluation_root or not work.is_relative_to(evaluation_root):
        raise SystemExit("self-test work-dir must be below the evaluation directory")
    source_root = work / "sources"
    out = work / "frozen"
    source_root.mkdir(parents=True, exist_ok=True)
    sources = {
        "case_1.cpp": "int f(int x) { return x; }\n",
        "case_2.cpp": "int g(int x) { return x + 1; }\n",
        "case_3.cpp": "int h(int x) { return x - 1; }\n",
    }
    for name, text in sources.items():
        (source_root / name).write_text(text, encoding="utf-8")
    protocol = {
        "schema": PROTOCOL_SCHEMA, "protocol_id": "G13-HP-SYNTHETIC-SELFTEST",
        "status": "FROZEN_NOT_EXECUTED", "execution_mode": "pipeline_self_test",
        "sampling_frame": {"required_case_identity": sorted(REQUIRED_CASE_IDENTITY)},
        "double_blind_review": {
            "reviewers": 2, "reviewer_count": 2, "adjudicators": 1, "adjudicator_count": 1,
            "allowed_labels": sorted(ALLOWED_LABELS),
            "reviewer_attestations": list(REVIEWER_ATTESTATIONS),
            "adjudicator_attestations": list(ADJUDICATOR_ATTESTATIONS),
            "reviewer_independence_required": True,
        },
        "metric_gate": {"required_conditions": [
            "protocol_file_hash_verified", "truth_commitment_verified",
            "truth_status_reliable_independent_human_adjudicated", "model_generated_false",
            "development_overlap_false", "reviewer_independence_attested", "adjudication_complete",
            "source_identity_complete", "case_set_exact", "no_unknown_labels",
        ]},
        "secret_handling": {"commit_secrets_to_git": False},
    }
    protocol_path = work / "protocol.json"
    write_json(protocol_path, protocol)
    cases = []
    labels = {}
    for idx, name in enumerate(sources, 1):
        case_id = f"SYNTHETIC-{idx}"
        data = (source_root / name).read_bytes()
        cases.append({
            "case_id": case_id, "source_path": name, "source_sha256": sha256_bytes(data),
            "repository": "synthetic://local", "commit": f"synthetic-commit-{idx}",
            "tree": f"synthetic-tree-{idx}", "blob": f"synthetic-blob-{idx}",
            "parser_identity": "tree-sitter-cpp-selftest", "snapshot_sha256": f"{idx:064x}",
            "selection_rule_id": "selftest-stratified", "sampling_frame_sha256": "3" * 64,
            "family_split": "holdout", "family_id": f"family-{idx}",
            "development_overlap": False, "development_leakage_match": False,
        })
        labels[case_id] = {"label": "vulnerable_shape" if idx == 1 else "not_vulnerable_shape", "model_generated": False}
    truth = {
        "schema": TRUTH_SCHEMA, "execution_mode": "pipeline_self_test",
        "truth_status": "pipeline_self_test_not_reliable", "model_generated": False,
        "scanner_outputs_used": False, "development_artifacts_used": False,
        "model_outputs_used": False, "labels": labels,
    }
    selection_frame_sha256 = payload_hash(protocol["sampling_frame"])
    for case in cases:
        case["sampling_frame_sha256"] = selection_frame_sha256
    development_leakage_ledger = {
        "schema": LEDGER_SCHEMA,
        "status": "COMPLETE_LOCAL_DEVELOPMENT_ARTIFACTS",
        "generated_at": "2026-10-19T00:00:00+08:00",
        "protocol_file_sha256": file_sha256(protocol_path),
        "selection_frame_sha256": selection_frame_sha256,
        "development_artifact_roots": ["research/evaluation/ark_runtime_holdout_20261019/selftest-c13-source-decoys"],
        "excluded_case_ids": ["SELFTEST-EXCLUDED-DEVELOPMENT-CASE"],
        "excluded_sources": [{
            "reason": "synthetic development decoy excluded from holdout self-test",
            "repository_path": "research/evaluation/ark_runtime_holdout_20261019/selftest-c13-source-decoys/decoy.cpp",
            "source_identity": {"role": "synthetic_development_decoy"},
            "bytes": 16,
            "sha256": sha256_bytes(b"development decoy"),
        }],
        "excluded_source_sha256": [sha256_bytes(b"development decoy")],
        "case_set_commitment_sha256": payload_hash(["SELFTEST-EXCLUDED-DEVELOPMENT-CASE"]),
        "coverage": {
            "roots_complete": True,
            "known_case_manifest_sha256": "0" * 64,
            "product_gate_payload_sha256": "0" * 64,
            "limitations": ["synthetic self-test ledger is not real holdout evidence"],
        },
    }
    development_leakage_ledger["payload_sha256"] = payload_hash(development_leakage_ledger)
    development_leakage_ledger_path = work / "development_leakage_ledger.json"
    write_json(development_leakage_ledger_path, development_leakage_ledger)
    intake = {
        "schema": INTAKE_SCHEMA, "execution_mode": "pipeline_self_test",
        "protocol_file_sha256": file_sha256(protocol_path), "preregistration_sha256": "1" * 64,
        "development_leakage_ledger_sha256": file_sha256(development_leakage_ledger_path),
        "development_leakage_ledger_payload_sha256": development_leakage_ledger["payload_sha256"],
        "family_split_sha256": "4" * 64,
        "sample_size": 3, "cases": cases,
    }
    secret_file = work / "selftest-secret.txt"
    secret_file.write_text("self-test-secret-not-for-real-holdout\n", encoding="utf-8")
    write_json(work / "intake.json", intake)
    write_json(work / "truth.json", truth)
    freeze(argparse.Namespace(cases=work / "intake.json", truth=work / "truth.json", protocol=protocol_path, development_leakage_ledger=development_leakage_ledger_path, source_root=source_root, output_dir=out, secret_file=secret_file))
    manifest = load_json(out / "freeze_manifest.json")
    packet_a = load_json(out / "reviewer_packet_A.json")
    packet_b = load_json(out / "reviewer_packet_B.json")
    attestations = {name: True for name in REVIEWER_ATTESTATIONS}
    a_rows, b_rows = [], []
    for idx, pseudo in enumerate(manifest["case_pseudonyms"]):
        a_label = "vulnerable_shape" if idx == 0 else "not_vulnerable_shape"
        b_label = "unknown" if idx == 0 else a_label
        a_rows.append({"case_pseudonym": pseudo, "label": a_label, "confidence": "high", "rationale": "self-test reviewer A source shape classification", "evidence": ["line 1"]})
        b_rows.append({"case_pseudonym": pseudo, "label": b_label, "confidence": "low", "rationale": "self-test reviewer B deliberately different classification", "evidence": ["line 1"]})
    sub_a = {"schema": REVIEW_SCHEMA, "reviewer_id": "A", "packet_sha256": payload_hash(packet_a), "independence_attestations": attestations, "labels": a_rows}
    sub_b = {"schema": REVIEW_SCHEMA, "reviewer_id": "B", "packet_sha256": payload_hash(packet_b), "independence_attestations": attestations, "labels": b_rows}
    write_json(work / "review_A.json", sub_a)
    write_json(work / "review_B.json", sub_b)
    lock_review(argparse.Namespace(freeze_manifest=out / "freeze_manifest.json", packet=out / "reviewer_packet_A.json", submission=work / "review_A.json", output=out / "review_A.lock.json"))
    lock_review(argparse.Namespace(freeze_manifest=out / "freeze_manifest.json", packet=out / "reviewer_packet_B.json", submission=work / "review_B.json", output=out / "review_B.lock.json"))
    adjudicate(argparse.Namespace(review_a=out / "review_A.lock.json", review_b=out / "review_B.lock.json", output=out / "adjudication_packet.json"))
    packet = load_json(out / "adjudication_packet.json")
    decisions = [{
        "case_pseudonym": row["case_pseudonym"],
        "decision": "unknown" if "unknown" in {row["reviewer_1_label"], row["reviewer_2_label"]} else "vulnerable_shape",
        "rationale": "self-test independent adjudicator source shape decision",
        "evidence": ["line 1"],
    } for row in packet["disagreements"]]
    adjudication_submission = {
        "schema": ADJUDICATION_SUBMISSION_SCHEMA, "freeze_payload_sha256": packet["freeze_payload_sha256"],
        "independence_attestations": {name: True for name in ADJUDICATOR_ATTESTATIONS},
        "decisions": decisions,
    }
    write_json(work / "adjudication_submission.json", adjudication_submission)
    apply_adjudication(argparse.Namespace(adjudication_packet=out / "adjudication_packet.json", adjudication_submission=work / "adjudication_submission.json", output=out / "final_labels.json"))
    result = {
        "schema": "ohscanner.ark-holdout-selftest/v2", "status": "PASS",
        "metrics_computed": False,
        "reason": "synthetic self-test truth is not reliable independent human truth",
    }
    write_json(work / "selftest-validation.json", result)
    print(json.dumps(result, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("freeze")
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--truth", type=Path, required=True)
    p.add_argument("--protocol", type=Path, required=True)
    p.add_argument("--development-leakage-ledger", type=Path, required=True)
    p.add_argument("--source-root", type=Path, required=True)
    p.add_argument("--secret-file", type=Path, required=True)
    p.add_argument("--output-dir", type=Path, required=True)
    p.set_defaults(func=freeze)
    p = sub.add_parser("lock-review")
    p.add_argument("--freeze-manifest", type=Path, required=True)
    p.add_argument("--packet", type=Path, required=True)
    p.add_argument("--submission", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=lock_review)
    p = sub.add_parser("adjudicate")
    p.add_argument("--review-a", type=Path, required=True)
    p.add_argument("--review-b", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=adjudicate)
    p = sub.add_parser("apply-adjudication")
    p.add_argument("--adjudication-packet", type=Path, required=True)
    p.add_argument("--adjudication-submission", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=apply_adjudication)
    p = sub.add_parser("score")
    p.add_argument("--truth", type=Path, required=True)
    p.add_argument("--final-labels", type=Path, required=True)
    p.add_argument("--freeze-manifest", type=Path, required=True)
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--protocol", type=Path, required=True)
    p.add_argument("--development-leakage-ledger", type=Path, required=True)
    p.add_argument("--secret-file", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    p.set_defaults(func=score)
    p = sub.add_parser("self-test")
    p.add_argument("--work-dir", type=Path, required=True)
    p.set_defaults(func=self_test)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
