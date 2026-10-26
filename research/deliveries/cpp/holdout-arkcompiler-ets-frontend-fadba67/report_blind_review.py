"""Validate independent blind labels and summarize the frozen holdout review."""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
from collections import Counter, defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
MANIFEST = HERE / "blind_manifest.json"
CENSUS = HERE / "component_census.json"
PACKET = HERE / "blind_packet.md"
LABELS = HERE / "reviewer_labels.csv"
ATTESTATION = HERE / "review_attestation.json"
FREEZE = HERE.parent / "ark-runtime-c-line-algorithm-freeze-20261018.json"
ALLOWED_SCOPE = {"in_scope", "out_of_scope", "uncertain"}
ALLOWED_LABELS = {"candidate", "partial", "blocked", "safe", "unknown"}
REQUIRED_EVIDENCE_COLUMNS = ("evidence_lines",)
ROOT_CAUSE_LABELS = {"candidate", "partial", "blocked", "safe"}
_PREPARE_SPEC = importlib.util.spec_from_file_location(
    "c_line_holdout_prepare_for_report", HERE / "prepare_blind_review.py"
)
assert _PREPARE_SPEC and _PREPARE_SPEC.loader
_PREPARE = importlib.util.module_from_spec(_PREPARE_SPEC)
_PREPARE_SPEC.loader.exec_module(_PREPARE)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_and_summarize(manifest: dict, census: dict, rows: list[dict], attestation: dict,
                           *, root: Path = ROOT, packet_path: Path = PACKET,
                           labels_path: Path = LABELS) -> dict:
    errors = []
    freeze = json.loads(FREEZE.read_text(encoding="utf-8"))
    freeze_relative = str(FREEZE.relative_to(ROOT)).replace("\\", "/")
    if manifest.get("algorithm_freeze") != freeze_relative:
        errors.append("packet does not point to the expected algorithm freeze")
    freeze_sha256 = sha256(FREEZE)
    if manifest.get("algorithm_freeze_sha256") != freeze_sha256:
        errors.append("packet algorithm freeze SHA-256 is missing or stale")
    if manifest.get("current_binding_version") != freeze.get("detector_version"):
        errors.append("packet detector version differs from the algorithm freeze")
    for relative_path, expected in {
        **freeze.get("implementation_sha256", {}),
        **freeze.get("implementation_support_sha256", {}),
    }.items():
        path = root / relative_path
        if not path.is_file() or sha256(path) != expected.lower():
            errors.append("algorithm freeze drift:" + relative_path)
    if (census.get("provenance", {}).get("commit"), census.get("provenance", {}).get("tree")) != (
            manifest["source"]["commit"], manifest["source"]["tree"]):
        errors.append("component census source identity differs from the blind packet")
    census_bytes = (HERE / "component_census.json").read_bytes()
    if hashlib.sha256(census_bytes).hexdigest() != manifest["component_census"].get("census_sha256"):
        errors.append("component census content hash does not match the prepared manifest")
    if sha256(packet_path) != manifest.get("packet_sha256"):
        errors.append("blind packet content hash does not match the prepared packet")
    packet_integrity = _PREPARE.packet_issues(
        manifest, census, rows, packet_path.read_text(encoding="utf-8"), require_blank_labels=False
    )
    errors.extend("packet integrity: " + issue for issue in packet_integrity)
    expected_ids = ["F001"] + [row["sample_id"] for row in manifest["selection"]["additional_samples"]]
    actual_ids = [row.get("sample_id", "") for row in rows]
    if actual_ids != expected_ids:
        errors.append("labels must contain every sample exactly once and in packet order")
    if len(rows) != manifest["review"]["sample_count"]:
        errors.append("label row count does not match the frozen sample count")

    for index, row in enumerate(rows, start=1):
        sample_id = row.get("sample_id") or f"row-{index}"
        scope, label = row.get("model_scope", ""), row.get("evidence_label", "")
        if scope not in ALLOWED_SCOPE:
            errors.append(f"{sample_id}: model_scope must be one of {sorted(ALLOWED_SCOPE)}")
        if label not in ALLOWED_LABELS:
            errors.append(f"{sample_id}: evidence_label must be one of {sorted(ALLOWED_LABELS)}")
        if any(not row.get(column, "").strip() for column in REQUIRED_EVIDENCE_COLUMNS):
            errors.append(f"{sample_id}: cite exact evidence lines")
        if label in ROOT_CAUSE_LABELS and not row.get("root_cause", "").strip():
            errors.append(f"{sample_id}: root_cause is required for {label}")
        if label == "unknown" and not row.get("unknown_reason", "").strip():
            errors.append(f"{sample_id}: unknown_reason is required")
        if label != "unknown" and row.get("unknown_reason", "").strip():
            errors.append(f"{sample_id}: unknown_reason must be blank for non-unknown labels")
    if attestation.get("independent_from_rule_development") is not True:
        errors.append("reviewer must attest independence from rule development")
    if attestation.get("saw_detector_output_before_labeling") is not False:
        errors.append("reviewer must attest detector output was not seen before labeling")
    if attestation.get("blind_packet_only_until_labels_completed") is not True:
        errors.append("reviewer must attest to blind packet-only access until labeling is complete")
    if attestation.get("reviewed_detector_version") != manifest.get("current_binding_version"):
        errors.append("reviewed detector version does not match the frozen packet")
    if not attestation.get("reviewer_role", "").strip() or not attestation.get("labels_completed_utc", "").strip():
        errors.append("reviewer role and completion timestamp are required")
    if errors:
        raise ValueError("; ".join(errors))

    label_counts = Counter(row["evidence_label"] for row in rows)
    scope_counts = Counter(row["model_scope"] for row in rows)
    root_causes: dict[str, Counter] = defaultdict(Counter)
    unknown_reasons = Counter()
    for row in rows:
        label = row["evidence_label"]
        if row.get("root_cause", "").strip():
            root_causes[label][row["root_cause"].strip()] += 1
        if label == "unknown":
            unknown_reasons[row["unknown_reason"].strip()] += 1

    component = manifest["component_census"]
    return {
        "schema": "c-line-blind-review-results-v1",
        "status": "complete",
        "detector": freeze["detector"],
        "detector_version": manifest["current_binding_version"],
        "algorithm_freeze": manifest["algorithm_freeze"],
        "algorithm_freeze_sha256": freeze_sha256,
        "source": {
            "repository": manifest["source"]["repository"],
            "commit": manifest["source"]["commit"],
            "tree": manifest["source"]["tree"],
        },
        "reviewer_attestation": {
            "reviewer_role": attestation["reviewer_role"],
            "independent_from_rule_development": True,
            "saw_detector_output_before_labeling": False,
            "blind_packet_only_until_labels_completed": True,
            "labels_completed_utc": attestation["labels_completed_utc"],
        },
        "coverage": {
            "labels_completed": len(rows),
            "samples_total": manifest["review"]["sample_count"],
            "sampled_translation_units": component["sampled_translation_units"],
            "complete_translation_units_in_frame": component["complete_files"],
            "translation_unit_coverage_fraction": component["complete_file_coverage_fraction"],
            "function_definitions_in_complete_files": component["function_definitions_in_complete_files"],
            "sampled_function_excerpts": component["sampled_function_excerpts"],
            "function_coverage_fraction": component["complete_function_coverage_fraction"],
            "partial_translation_units_in_frame": component["partial_files"],
        },
        "label_counts": dict(sorted(label_counts.items())),
        "scope_counts": dict(sorted(scope_counts.items())),
        "unknown": {
            "count": label_counts.get("unknown", 0),
            "reasons": dict(sorted(unknown_reasons.items())),
        },
        "root_causes_by_label": {
            label: dict(sorted(counts.items())) for label, counts in sorted(root_causes.items())
        },
        "provenance": {
            "blind_packet_sha256": sha256(packet_path),
            "labels_csv_sha256": sha256(labels_path),
            "census_sha256": hashlib.sha256(census_bytes).hexdigest(),
            "census_files": census["summary"]["tracked_cpp_files"],
        },
        "interpretation_limit": "Applicability/false-match review only; this frame does not test semantic recall or estimate component-wide precision/recall.",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--labels", type=Path, default=LABELS)
    parser.add_argument("--attestation", type=Path, default=ATTESTATION)
    parser.add_argument("--output", type=Path, default=HERE / "review_results.json")
    args = parser.parse_args()
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    census = json.loads(CENSUS.read_text(encoding="utf-8"))
    attestation = json.loads(args.attestation.read_text(encoding="utf-8"))
    with args.labels.open(encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    result = validate_and_summarize(manifest, census, rows, attestation,
                                    packet_path=PACKET, labels_path=args.labels)
    args.output.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n",
                           encoding="utf-8", newline="\n")
    print(f"review_report={args.output}; samples={len(rows)}; unknown={result['unknown']['count']}")


if __name__ == "__main__":
    main()
