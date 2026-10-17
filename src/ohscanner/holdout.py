"""Frozen independent holdout identities, validation and fail-closed metrics."""
from __future__ import annotations

from collections import Counter, defaultdict
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

FAMILY_MIN_ROOT_CAUSES = 5
_FAMILIES = {
    "cpp.null_dereference": {
        "detector_id": "ohscanner.cpp.null_dereference",
        "cwe": ["CWE-476"],
    },
    "cpp.lifetime_uaf": {
        "detector_id": "ohscanner.cpp.lifetime",
        "cwe": ["CWE-416"],
    },
    "cpp.resource_lifetime": {
        "detector_id": "ohscanner.cpp.resource_lifetime",
        "cwe": ["CWE-401", "CWE-415", "CWE-772"],
    },
    "cpp.bounds": {
        "detector_id": "ohscanner.cpp.bounds",
        "cwe": ["CWE-125", "CWE-787"],
    },
    "cpp.integer_bounds": {
        "detector_id": "ohscanner.cpp.integer_bounds",
        "cwe": ["CWE-190", "CWE-191"],
    },
    "cpp.unsafe_memory_call": {
        "detector_id": "ohscanner.cpp.unsafe_memory_call",
        "cwe": ["CWE-120", "CWE-787"],
    },
}
_SHA40 = re.compile(r"[a-f0-9]{40}")
_SHA64 = re.compile(r"[a-f0-9]{64}")


def canonical_digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def write_freeze_files(manifest: Mapping[str, Any], output_dir: Path) -> dict[str, str]:
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = output_dir / "holdout_manifest.json"
    payload = json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    manifest_path.write_bytes(payload.encode("utf-8"))
    manifest_sha = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    freeze = {
        "schema_version": 1,
        "kind": "ohscanner.independent-holdout-freeze.v1",
        "manifest_sha256": manifest_sha,
        "canonical_content_digest": canonical_digest(manifest),
    }
    freeze_path = output_dir / "FREEZE.sha256"
    freeze_path.write_text(
        manifest_sha + "  holdout_manifest.json\n"
        + freeze["canonical_content_digest"] + "  canonical-content\n",
        encoding="utf-8",
    )
    return {
        "manifest_path": str(manifest_path),
        "manifest_sha256": manifest_sha,
        "canonical_content_digest": freeze["canonical_content_digest"],
        "freeze_path": str(freeze_path),
    }


def verify_freeze(manifest: Mapping[str, Any]) -> None:
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported holdout manifest schema")
    if manifest.get("kind") != "ohscanner.independent-holdout.v1":
        raise ValueError("not an independent holdout manifest")
    if manifest.get("eligible_for_metrics") is not True:
        raise ValueError("holdout manifest is not eligible for metrics")
    if manifest.get("truth_independence") != "official-public-fix-labels":
        raise ValueError("truth is not independent official fix evidence")
    if manifest.get("detector_tuning_after_freeze") is not False:
        raise ValueError("holdout freeze does not prohibit detector tuning")
    if manifest.get("family_min_root_causes") != FAMILY_MIN_ROOT_CAUSES:
        raise ValueError("unexpected family publication threshold")
    cases = manifest.get("root_causes")
    if not isinstance(cases, list) or len(cases) != 30:
        raise ValueError("holdout must contain exactly 30 root causes")
    names = set()
    commits = set()
    patch_ids = set()
    families = Counter()
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError("invalid holdout root cause")
        name = case.get("root_cause_id")
        if not isinstance(name, str) or not name or name in names:
            raise ValueError("duplicate or invalid root cause ID")
        names.add(name)
        family = case.get("family")
        if family not in _FAMILIES:
            raise ValueError("unknown holdout rule family")
        families[family] += 1
        if case.get("detector_id") != _FAMILIES[family]["detector_id"]:
            raise ValueError("family/detector mismatch")
        commit = case.get("fix_commit")
        parent = case.get("vulnerable_parent")
        tree_fix = case.get("fix_tree")
        tree_parent = case.get("vulnerable_tree")
        for label, value in (
            ("fix_commit", commit), ("vulnerable_parent", parent),
            ("fix_tree", tree_fix), ("vulnerable_tree", tree_parent),
        ):
            if not isinstance(value, str) or not _SHA40.fullmatch(value):
                raise ValueError("invalid " + label)
        if commit in commits:
            raise ValueError("duplicate fix commit")
        commits.add(commit)
        patch_id = case.get("stable_patch_id")
        if not isinstance(patch_id, str) or not (_SHA40.fullmatch(patch_id) or _SHA64.fullmatch(patch_id)):
            raise ValueError("invalid stable patch ID")
        if patch_id in patch_ids:
            raise ValueError("duplicate stable patch ID")
        patch_ids.add(patch_id)
        if case.get("cwe") not in _FAMILIES[family]["cwe"]:
            raise ValueError("unsupported CWE for family")
        if case.get("cve_id") is not None and not re.fullmatch(r"CVE-[0-9]{4}-[0-9]+", case["cve_id"]):
            raise ValueError("invalid CVE identifier")
        if not isinstance(case.get("official_reference"), str) or not case["official_reference"].startswith("https://"):
            raise ValueError("missing official public fix reference")
        for category in ("vulnerable", "fixed"):
            sample = case.get(category)
            if not isinstance(sample, dict) or sample.get("category") != category:
                raise ValueError("invalid holdout sample category")
            if sample.get("commit") != (parent if category == "vulnerable" else commit):
                raise ValueError("sample commit mismatch")
            if sample.get("tree") != (tree_parent if category == "vulnerable" else tree_fix):
                raise ValueError("sample tree mismatch")
            files = sample.get("files")
            if not isinstance(files, list) or not files:
                raise ValueError("holdout sample has no files")
            seen = set()
            for row in files:
                if not isinstance(row, dict):
                    raise ValueError("invalid source identity")
                path = row.get("path")
                blob = row.get("blob_oid")
                source = row.get("source_sha256")
                if not isinstance(path, str) or path in seen:
                    raise ValueError("duplicate/invalid holdout source path")
                seen.add(path)
                if not isinstance(blob, str) or not _SHA40.fullmatch(blob):
                    raise ValueError("invalid holdout blob OID")
                if not isinstance(source, str) or not _SHA64.fullmatch(source):
                    raise ValueError("invalid holdout source SHA-256")
        for field in ("entry", "attacker_control", "trigger", "repair", "limitations"):
            if not isinstance(case.get(field), str) or not case[field].strip():
                raise ValueError("missing required holdout evidence field")
    missing = sorted(set(_FAMILIES) - set(families))
    if missing:
        raise ValueError("holdout lacks required families: " + ", ".join(missing))
    insufficient = sorted(name for name, count in families.items() if count < FAMILY_MIN_ROOT_CAUSES)
    if insufficient:
        raise ValueError("holdout family below publication threshold: " + ", ".join(insufficient))


def truth_records(manifest: Mapping[str, Any]) -> list[dict[str, Any]]:
    verify_freeze(manifest)
    rows: list[dict[str, Any]] = []
    for case in manifest["root_causes"]:
        for category in ("vulnerable", "fixed"):
            sample = case[category]
            rows.append({
                "sample_id": sample["sample_id"],
                "root_cause_id": case["root_cause_id"],
                "family": case["family"],
                "detector_id": case["detector_id"],
                "category": category,
                "split": "holdout",
                "truth_verified": True,
                "truth_source": case["official_reference"],
                "fix_commit": case["fix_commit"],
                "vulnerable_parent": case["vulnerable_parent"],
            })
    return sorted(rows, key=lambda item: item["sample_id"])


def summarize_predictions(
    manifest: Mapping[str, Any],
    predictions: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    verify_freeze(manifest)
    by_sample = {str(row.get("sample_id")): row for row in predictions}
    expected = {row["sample_id"] for row in truth_records(manifest)}
    if set(by_sample) != expected:
        raise ValueError("prediction sample set differs from frozen holdout")
    sample_rows: list[dict[str, Any]] = []
    root_rows: list[dict[str, Any]] = []
    family_buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
    totals = Counter()
    unknown = []
    for case in manifest["root_causes"]:
        case_predictions = []
        for category in ("vulnerable", "fixed"):
            sample_id = case[category]["sample_id"]
            row = by_sample[sample_id]
            prediction = row.get("prediction")
            if prediction not in ("detected", "not_detected", "unknown"):
                prediction = "unknown"
            record = {
                "sample_id": sample_id,
                "root_cause_id": case["root_cause_id"],
                "family": case["family"],
                "truth": category,
                "prediction": prediction,
                "detector_id": case["detector_id"],
                "detector_status": row.get("detector_status"),
                "diagnostic_count": row.get("diagnostic_count"),
                "coverage": row.get("coverage"),
            }
            sample_rows.append(record)
            case_predictions.append(record)
            if prediction == "unknown":
                unknown.append(record)
                continue
            outcome = {
                ("vulnerable", "detected"): "TP",
                ("vulnerable", "not_detected"): "FN",
                ("fixed", "detected"): "FP",
                ("fixed", "not_detected"): "TN",
            }[(category, prediction)]
            totals[outcome] += 1
            family_buckets[case["family"]].append(record | {"outcome": outcome})
        vulnerable_row = next(row for row in case_predictions if row["truth"] == "vulnerable")
        fixed_row = next(row for row in case_predictions if row["truth"] == "fixed")
        root_outcome = {
            "detected": "TP",
            "not_detected": "FN",
            "unknown": "unable_to_analyze",
        }[vulnerable_row["prediction"]]
        fixed_outcome = {
            "detected": "FP",
            "not_detected": "TN",
            "unknown": "unable_to_analyze",
        }[fixed_row["prediction"]]
        root_rows.append({
            "root_cause_id": case["root_cause_id"],
            "family": case["family"],
            "vulnerable_outcome": root_outcome,
            "fixed_outcome": fixed_outcome,
            "sample_ids": [row["sample_id"] for row in case_predictions],
        })

    def metrics(
        counter: Counter[str],
        *,
        eligible: bool,
        total_samples: int,
        unable_to_analyze_count: int,
    ) -> dict[str, Any]:
        observed = {key: counter[key] for key in ("TP", "FP", "FN", "TN")}
        tp, fp, fn, tn = (observed[key] for key in ("TP", "FP", "FN", "TN"))
        precision = tp / (tp + fp) if eligible and tp + fp else None
        recall = tp / (tp + fn) if eligible and tp + fn else None
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision is not None and recall is not None and precision + recall
            else None
        )
        return {
            "eligible_for_metrics": eligible,
            "coverage_complete": unable_to_analyze_count == 0,
            "metric_scope": "known-scored-samples-only" if eligible else "not-published",
            "scored_samples": sum(observed.values()),
            "total_samples": total_samples,
            "unable_to_analyze_count": unable_to_analyze_count,
            "observed_counts": observed,
            **observed,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }

    family_metrics = {}
    for family in sorted(_FAMILIES):
        rows = family_buckets.get(family, [])
        counts = Counter(row["outcome"] for row in rows)
        root_count = sum(1 for row in root_rows if row["family"] == family)
        total_samples = root_count * 2
        unknown_count = total_samples - len(rows)
        complete = root_count >= FAMILY_MIN_ROOT_CAUSES and unknown_count == 0
        family_metrics[family] = {
            "root_causes": root_count,
            **metrics(
                counts,
                eligible=complete,
                total_samples=total_samples,
                unable_to_analyze_count=unknown_count,
            ),
        }
    total_samples = len(manifest["root_causes"]) * 2

    return {
        "schema_version": 1,
        "kind": "ohscanner.independent-holdout-results.v1",
        "holdout_manifest_sha256": canonical_digest(manifest),
        "independent_holdout": True,
        "detector_tuning_after_freeze": False,
        "sample_level": metrics(
            totals, eligible=bool(totals), total_samples=total_samples,
            unable_to_analyze_count=len(unknown),
        ),
        "family_metrics": family_metrics,
        "root_cause_level": {
            "root_causes": root_rows,
            "vulnerable_axis_counts": dict(sorted(Counter(row["vulnerable_outcome"] for row in root_rows).items())),
            "fixed_axis_counts": dict(sorted(Counter(row["fixed_outcome"] for row in root_rows).items())),
        },
        "samples": sorted(sample_rows, key=lambda row: row["sample_id"]),
        "unable_to_analyze": unknown,
        "interpretation": (
            "Metrics use official public vulnerable/fixed fix pairs as independent "
            "code-defect truth. They do not establish exploitability or product CIA impact."
        ),
    }


def save_json(path: Path, value: Any) -> str:
    payload = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload.encode("utf-8"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
