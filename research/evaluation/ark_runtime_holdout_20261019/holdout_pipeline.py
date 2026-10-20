#!/usr/bin/env python3
"""Independent holdout freeze, double-blind review and adjudication pipeline.

The pipeline separates source intake, truth custody, reviewer packets and
adjudication. It refuses Precision/Recall unless the truth packet explicitly
declares reliable independent human labels and is not model-generated.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import shutil
from pathlib import Path, PurePosixPath
from typing import Any

FREEZE_SCHEMA = "ohscanner.ark-holdout-freeze/v1"
INTAKE_SCHEMA = "ohscanner.ark-holdout-intake/v1"
TRUTH_SCHEMA = "ohscanner.ark-holdout-truth/v1"
REVIEW_SCHEMA = "ohscanner.ark-holdout-review/v1"
LOCK_SCHEMA = "ohscanner.ark-holdout-review-lock/v1"
ADJUDICATION_SCHEMA = "ohscanner.ark-holdout-adjudication/v1"
FINAL_SCHEMA = "ohscanner.ark-holdout-final-labels/v1"
ALLOWED_LABELS = {"vulnerable_shape", "not_vulnerable_shape", "unknown"}


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def payload_hash(value: Any) -> str:
    return sha256_bytes(canonical_json_bytes(value))


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
    errors: list[str] = []
    forbidden = {
        "case_id_in_source": case_id in text,
        "source_path_in_source": source_path in text,
        "url_in_source": bool(re.search(r"https?://", text, re.IGNORECASE)),
        "cve_identifier_in_source": bool(re.search(r"CVE-\d{4}-\d+", text, re.IGNORECASE)),
        "issue_or_pull_reference_in_source": bool(re.search(r"(issues?/\d+|pulls?/\d+|![0-9]{3,})", text, re.IGNORECASE)),
    }
    errors.extend("source_metadata_leak:" + key for key, present in forbidden.items() if present)
    return errors

def pseudonym(secret: bytes, case_id: str) -> str:
    return hmac.new(secret, case_id.encode("utf-8"), hashlib.sha256).hexdigest()[:16]


def validate_intake(intake: dict[str, Any], truth: dict[str, Any], source_root: Path) -> list[str]:
    errors: list[str] = []
    if intake.get("schema") != INTAKE_SCHEMA:
        errors.append("intake_schema")
    if truth.get("schema") != TRUTH_SCHEMA:
        errors.append("truth_schema")
    if not intake.get("preregistration_sha256"):
        errors.append("missing_preregistration_sha256")
    if not intake.get("development_leakage_ledger_sha256"):
        errors.append("missing_development_leakage_ledger_sha256")
    cases = intake.get("cases", [])
    labels = truth.get("labels", {})
    ids = [case.get("case_id") for case in cases]
    if len(ids) != len(set(ids)):
        errors.append("duplicate_case_id")
    if set(ids) != set(labels):
        errors.append("truth_case_set_mismatch")
    for case in cases:
        case_id = case.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            errors.append("empty_case_id")
            continue
        if case.get("development_overlap") is not False:
            errors.append(f"development_overlap_not_false:{case_id}")
        if not case.get("selection_rule_id") or not case.get("sampling_frame_sha256"):
            errors.append(f"missing_selection_binding:{case_id}")
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
        digest = sha256_bytes(data)
        errors.extend(source_leak_errors(data, case_id, source_path))
        expected = case.get("source_sha256")
        if expected and expected != digest:
            errors.append(f"source_sha256_mismatch:{case_id}")
        entry = labels.get(case_id, {})
        if entry.get("label") not in ALLOWED_LABELS:
            errors.append(f"invalid_truth_label:{case_id}")
        if entry.get("model_generated") is not False:
            errors.append(f"truth_model_generated:{case_id}")
    return errors


def freeze(args: argparse.Namespace) -> int:
    intake = load_json(args.cases)
    truth = load_json(args.truth)
    source_root = args.source_root.resolve()
    errors = validate_intake(intake, truth, source_root)
    if errors:
        raise SystemExit("freeze rejected: " + ", ".join(errors))
    secret = args.secret_file.read_bytes().strip()
    if not secret:
        raise SystemExit("empty custodian secret")
    cases = intake["cases"]
    rows = []
    packets = {}
    for case in cases:
        case_id = case["case_id"]
        data = source_root.joinpath(*PurePosixPath(case["source_path"]).parts).read_bytes()
        pseudo = pseudonym(secret, case_id)
        row = {
            "case_pseudonym": pseudo,
            "source_sha256": sha256_bytes(data),
            "source_bytes": len(data),
            "selection_rule_id": case["selection_rule_id"],
            "sampling_frame_sha256": case["sampling_frame_sha256"],
            "development_overlap": False,
        }
        rows.append(row)
        packets[pseudo] = {
            "case_pseudonym": pseudo,
            "source_text": data.decode("utf-8", errors="replace"),
            "source_sha256": row["source_sha256"],
            "question": "Classify only the source shape. Use vulnerable_shape, not_vulnerable_shape, or unknown. Do not infer product exploitability.",
            "forbidden_context": ["true label", "case id", "source path", "parent/fixed pairing", "scanner verdict"],
        }
    rows.sort(key=lambda item: item["case_pseudonym"])
    public_packet = {"schema": REVIEW_SCHEMA, "reviewer": "A", "cases": [packets[row["case_pseudonym"]] for row in rows]}
    packet_b = {"schema": REVIEW_SCHEMA, "reviewer": "B", "cases": [packets[row["case_pseudonym"]] for row in reversed(rows)]}
    truth_commitment = payload_hash({"schema": truth["schema"], "labels": truth["labels"], "truth_status": truth.get("truth_status")})
    manifest = {
        "schema": FREEZE_SCHEMA,
        "status": "FROZEN_PIPELINE_ONLY",
        "truth_status": truth.get("truth_status"),
        "truth_commitment_sha256": truth_commitment,
        "case_count": len(rows),
        "case_pseudonyms": [row["case_pseudonym"] for row in rows],
        "public_case_rows": rows,
        "review_protocol": {
            "reviewers": 2,
            "reviewer_independence_required": True,
            "labels": sorted(ALLOWED_LABELS),
            "adjudicator": 1,
            "agreement_rule": "matching labels are accepted; disagreements require a third blind adjudication decision",
            "model_generated_truth_forbidden": True,
            "metrics_rule": "Precision/Recall is refused unless truth_status == reliable_independent_human_adjudicated",
        },
        "packet_payload_sha256": {
            "A": payload_hash(public_packet),
            "B": payload_hash(packet_b),
        },
    }
    manifest["payload_sha256"] = payload_hash(manifest)
    out = args.output_dir
    out.mkdir(parents=True, exist_ok=True)
    write_json(out / "freeze_manifest.json", manifest)
    write_json(out / "reviewer_packet_A.json", public_packet)
    write_json(out / "reviewer_packet_B.json", packet_b)
    write_json(out / "truth_commitment.json", {"schema": "ohscanner.ark-holdout-truth-commitment/v1", "sha256": truth_commitment})
    write_json(out / "adjudication_template.json", {
        "schema": ADJUDICATION_SCHEMA,
        "freeze_payload_sha256": manifest["payload_sha256"],
        "decisions": [],
        "required_fields": ["case_pseudonym", "decision", "rationale"],
    })
    print(json.dumps({"status": manifest["status"], "case_count": len(rows), "truth_status": manifest["truth_status"]}, indent=2))
    return 0


def validate_submission(freeze_manifest: dict[str, Any], packet: dict[str, Any], submission: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if submission.get("schema") != REVIEW_SCHEMA:
        errors.append("submission_schema")
    if submission.get("packet_sha256") != payload_hash(packet):
        errors.append("packet_hash_mismatch")
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
        if not row.get("rationale"):
            errors.append(f"missing_rationale:{pseudo}")
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
        "schema": LOCK_SCHEMA,
        "freeze_payload_sha256": freeze_manifest["payload_sha256"],
        "reviewer": packet.get("reviewer"),
        "submission_payload_sha256": payload_hash(submission),
        "labels": sorted(submission["labels"], key=lambda item: item["case_pseudonym"]),
    }
    lock["payload_sha256"] = payload_hash(lock)
    write_json(args.output, lock)
    print(json.dumps({"status": "LOCKED", "reviewer": lock["reviewer"], "payload_sha256": lock["payload_sha256"]}, indent=2))
    return 0


def adjudicate(args: argparse.Namespace) -> int:
    a = load_json(args.review_a)
    b = load_json(args.review_b)
    if a.get("freeze_payload_sha256") != b.get("freeze_payload_sha256"):
        raise SystemExit("review freeze mismatch")
    a_rows = {row["case_pseudonym"]: row for row in a["labels"]}
    b_rows = {row["case_pseudonym"]: row for row in b["labels"]}
    if set(a_rows) != set(b_rows):
        raise SystemExit("review case set mismatch")
    agreements = []
    disagreements = []
    for pseudo in sorted(a_rows):
        left, right = a_rows[pseudo], b_rows[pseudo]
        if left["label"] == right["label"]:
            agreements.append({"case_pseudonym": pseudo, "label": left["label"], "route": "agreement"})
        else:
            disagreements.append({
                "case_pseudonym": pseudo,
                "reviewer_1_label": left["label"],
                "reviewer_2_label": right["label"],
                "reviewer_1_rationale": left["rationale"],
                "reviewer_2_rationale": right["rationale"],
            })
    out = {
        "schema": ADJUDICATION_SCHEMA,
        "freeze_payload_sha256": a["freeze_payload_sha256"],
        "status": "THIRD_REVIEW_REQUIRED" if disagreements else "AGREEMENT_COMPLETE",
        "agreements": agreements,
        "disagreements": disagreements,
    }
    out["payload_sha256"] = payload_hash(out)
    write_json(args.output, out)
    print(json.dumps({"status": out["status"], "agreements": len(agreements), "disagreements": len(disagreements)}, indent=2))
    return 0


def apply_adjudication(args: argparse.Namespace) -> int:
    packet = load_json(args.adjudication_packet)
    submission = load_json(args.adjudication_submission)
    decisions = {row["case_pseudonym"]: row for row in submission.get("decisions", [])}
    final_rows = []
    for row in packet.get("agreements", []):
        final_rows.append({"case_pseudonym": row["case_pseudonym"], "label": row["label"], "route": "agreement"})
    for row in packet.get("disagreements", []):
        pseudo = row["case_pseudonym"]
        decision = decisions.get(pseudo)
        if not decision or decision.get("decision") not in ALLOWED_LABELS or not decision.get("rationale"):
            raise SystemExit(f"missing adjudication decision for {pseudo}")
        final_rows.append({"case_pseudonym": pseudo, "label": decision["decision"], "route": "third_review_adjudication"})
    out = {
        "schema": FINAL_SCHEMA,
        "freeze_payload_sha256": packet.get("freeze_payload_sha256"),
        "status": "FINAL_LABELS_AVAILABLE",
        "labels": sorted(final_rows, key=lambda item: item["case_pseudonym"]),
        "model_generated": False,
    }
    out["payload_sha256"] = payload_hash(out)
    write_json(args.output, out)
    print(json.dumps({"status": out["status"], "label_count": len(final_rows)}, indent=2))
    return 0


def score(args: argparse.Namespace) -> int:
    truth = load_json(args.truth)
    final = load_json(args.final_labels)
    if truth.get("truth_status") != "reliable_independent_human_adjudicated" or truth.get("model_generated") is not False:
        print(json.dumps({"status": "NOT_RUN", "reason": "truth is not reliable independent human adjudicated"}, indent=2))
        return 3
    secret = args.secret_file.read_bytes().strip()
    labels = {pseudonym(secret, case_id): row for case_id, row in truth["labels"].items()}
    predicted = {row["case_pseudonym"]: row["label"] for row in final["labels"]}
    matrix = {"TP": 0, "FP": 0, "FN": 0, "TN": 0, "unknown": 0}
    for pseudo, truth_row in labels.items():
        pred = predicted.get(pseudo, "unknown")
        true = truth_row["label"]
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
    out = {"schema": "ohscanner.ark-holdout-score/v1", "status": "COMPLETE", "confusion_matrix": matrix}
    write_json(args.output, out)
    print(json.dumps(out, indent=2))
    return 0


def self_test(args: argparse.Namespace) -> int:
    work = args.work_dir.resolve()
    evaluation_root = Path(__file__).resolve().parent
    if work == evaluation_root or not work.is_relative_to(evaluation_root):
        raise SystemExit("self-test work-dir must be a child of the evaluation directory")
    if work.exists():
        shutil.rmtree(work)
    source_root = work / "sources"
    out = work / "frozen"
    source_root.mkdir(parents=True)
    cases = []
    labels = {}
    for index, label in enumerate(("vulnerable_shape", "not_vulnerable_shape", "unknown"), start=1):
        case_id = f"SELFTEST-{index}"
        source_path = f"case_{index}.cpp"
        (source_root / source_path).write_text(f"// self-test source {index}\nint f_{index}(int x) {{ return x; }}\n", encoding="utf-8")
        cases.append({
            "case_id": case_id,
            "source_path": source_path,
            "selection_rule_id": "selftest-synthetic",
            "sampling_frame_sha256": "0" * 64,
            "development_overlap": False,
        })
        labels[case_id] = {"label": label, "model_generated": False, "root_cause_family": "synthetic"}
    intake = {"schema": INTAKE_SCHEMA, "preregistration_sha256": "1" * 64, "development_leakage_ledger_sha256": "2" * 64, "cases": cases}
    truth = {"schema": TRUTH_SCHEMA, "truth_status": "pipeline_self_test_not_reliable", "model_generated": False, "labels": labels}
    secret_file = work / "selftest-secret.txt"
    secret_file.write_text("self-test-secret-not-for-real-holdout\n", encoding="utf-8")
    write_json(work / "intake.json", intake)
    write_json(work / "truth.json", truth)
    freeze_ns = argparse.Namespace(cases=work / "intake.json", truth=work / "truth.json", source_root=source_root, output_dir=out, secret_file=secret_file)
    freeze(freeze_ns)
    manifest = load_json(out / "freeze_manifest.json")
    packet_a = load_json(out / "reviewer_packet_A.json")
    packet_b = load_json(out / "reviewer_packet_B.json")
    a_rows, b_rows = [], []
    for idx, pseudo in enumerate(manifest["case_pseudonyms"]):
        a_label = "vulnerable_shape" if idx == 0 else "not_vulnerable_shape"
        b_label = "unknown" if idx == 0 else a_label
        a_rows.append({"case_pseudonym": pseudo, "label": a_label, "rationale": "self-test reviewer A"})
        b_rows.append({"case_pseudonym": pseudo, "label": b_label, "rationale": "self-test reviewer B"})
    sub_a = {"schema": REVIEW_SCHEMA, "packet_sha256": payload_hash(packet_a), "labels": a_rows}
    sub_b = {"schema": REVIEW_SCHEMA, "packet_sha256": payload_hash(packet_b), "labels": b_rows}
    write_json(work / "review_A.json", sub_a)
    write_json(work / "review_B.json", sub_b)
    lock_review(argparse.Namespace(freeze_manifest=out / "freeze_manifest.json", packet=out / "reviewer_packet_A.json", submission=work / "review_A.json", output=out / "review_A.lock.json"))
    lock_review(argparse.Namespace(freeze_manifest=out / "freeze_manifest.json", packet=out / "reviewer_packet_B.json", submission=work / "review_B.json", output=out / "review_B.lock.json"))
    adjudicate(argparse.Namespace(review_a=out / "review_A.lock.json", review_b=out / "review_B.lock.json", output=out / "adjudication_packet.json"))
    packet = load_json(out / "adjudication_packet.json")
    decisions = [{"case_pseudonym": row["case_pseudonym"], "decision": "vulnerable_shape", "rationale": "self-test adjudicator"} for row in packet["disagreements"]]
    write_json(work / "adjudication_submission.json", {"schema": ADJUDICATION_SCHEMA, "freeze_payload_sha256": packet["freeze_payload_sha256"], "decisions": decisions})
    apply_adjudication(argparse.Namespace(adjudication_packet=out / "adjudication_packet.json", adjudication_submission=work / "adjudication_submission.json", output=out / "final_labels.json"))
    result = {"schema": "ohscanner.ark-holdout-selftest/v1", "status": "PASS", "metrics_computed": False, "reason": "synthetic self-test truth is not reliable independent human truth"}
    write_json(work / "selftest-validation.json", result)
    print(json.dumps(result, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("freeze")
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--truth", type=Path, required=True)
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