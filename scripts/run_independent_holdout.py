from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.catalog import build_registry
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.holdout import save_json, summarize_predictions, truth_records, verify_freeze
from src.ohscanner.runner import run_all_with_coverage
from src.parser.ast import parse_source


SOURCE_LANGUAGE = {
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".h": "cpp", ".hh": "cpp", ".hpp": "cpp",
}


def offline_git(repo: Path, *args: str) -> bytes:
    env = os.environ.copy()
    env.update({
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    result = subprocess.run(
        ["git", "-c", "remote.origin.promisor=false", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env, check=False, timeout=60,
    )
    if result.returncode:
        raise ValueError("offline Git object read failed: " + result.stderr.decode("utf-8", "replace")[:300])
    return result.stdout


def parse_roots(values: list[str]) -> dict[str, Path]:
    roots = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--repo-root requires key=path")
        key, raw = value.split("=", 1)
        path = Path(raw).resolve()
        if not path.is_dir() or path.is_symlink():
            raise ValueError("invalid repository root: " + raw)
        roots[key] = path
    return roots


def load_sample(repo: Path, case: dict[str, Any], sample: dict[str, Any]) -> tuple[ScanContext, dict[str, Any]]:
    commit = sample["commit"]
    tree = offline_git(repo, "rev-parse", "--verify", commit + "^{tree}").decode().strip()
    if tree != sample["tree"]:
        raise ValueError("sample tree mismatch for " + sample["sample_id"])
    units = []
    ast_summary = {}
    file_identity = {}
    for row in sorted(sample["files"], key=lambda item: item["path"]):
        oid = offline_git(repo, "rev-parse", commit + ":" + row["path"]).decode().strip()
        if oid != row["blob_oid"]:
            raise ValueError("sample blob mismatch for " + row["path"])
        data = offline_git(repo, "cat-file", "blob", oid)
        source_sha = hashlib.sha256(data).hexdigest()
        if source_sha != row["source_sha256"]:
            raise ValueError("sample source hash mismatch for " + row["path"])
        text = data.decode("utf-8")
        language = SOURCE_LANGUAGE[Path(row["path"]).suffix.lower()]
        index = parse_source(text, language=language)
        issues = tuple(str(item) for item in index.parse_issues)
        units.append(SourceUnit(
            path=row["path"], language=language, text=text, sha256=source_sha,
            parse_status=index.parse_status, parse_issues=issues,
        ))
        ast_summary[row["path"]] = {
            "parse_status": index.parse_status,
            "functions": [item.__dict__ for item in index.functions],
            "calls": [item.__dict__ for item in index.calls],
            "variables": [item.__dict__ for item in index.variables],
        }
        file_identity[row["path"]] = {
            "blob_oid": oid,
            "source_sha256": source_sha,
            "bytes": len(data),
            "lines": len(data.splitlines()),
            "parse_status": index.parse_status,
        }
    units_tuple = tuple(sorted(units, key=lambda item: item.path))
    request = ScanRequest(
        request_id="independent-holdout-20261017-single-run:" + sample["sample_id"],
        repository="openharmony/" + case["repository_root_key"],
        commit=commit,
        snapshot_sha256=snapshot_digest(units_tuple),
        target_id="current-component:openharmony/" + case["repository_root_key"],
        profile_id="light-ast",
        provenance="git_object",
    )
    context = ScanContext(request=request, units=units_tuple, shared_facts={"ast": ast_summary})
    return context, {
        "sample_id": sample["sample_id"],
        "commit": commit,
        "tree": tree,
        "snapshot_sha256": request.snapshot_sha256,
        "files": file_identity,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--freeze", type=Path, required=True)
    parser.add_argument("--repo-root", action="append", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists() and any(args.output_dir.iterdir()):
        raise ValueError("holdout output directory already exists; the frozen detector run must execute once")
    raw = args.manifest.read_bytes()
    expected = args.freeze.read_text(encoding="utf-8").splitlines()[0].split()[0]
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("holdout manifest does not match FREEZE.sha256")
    manifest = json.loads(raw)
    verify_freeze(manifest)
    roots = parse_roots(args.repo_root)
    detector_ids = tuple(row["detector_id"] for row in manifest["detector_bindings"])
    registry = build_registry(detector_ids)
    actual_versions = {item.detector_id: item.version for item in registry.detectors()}
    expected_versions = {row["detector_id"]: row["version"] for row in manifest["detector_bindings"]}
    if actual_versions != expected_versions:
        raise ValueError("detector version drift after holdout freeze")

    results = []
    predictions = []
    identities = []
    for case in manifest["root_causes"]:
        repo = roots[case["repository_root_key"]]
        for category in ("vulnerable", "fixed"):
            sample = case[category]
            context, identity = load_sample(repo, case, sample)
            identities.append(identity)
            reports, sidecar = run_all_with_coverage(context, registry)
            report_by_id = {row.tool: row.to_dict() for row in reports}
            relevant = report_by_id[case["detector_id"]]
            count = relevant["diagnostic_count"]
            coverage = sidecar["detectors"][case["detector_id"]]
            if relevant["status"] == "completed":
                prediction = "detected" if count else "not_detected"
            else:
                prediction = "unknown"
            prediction_row = {
                "sample_id": sample["sample_id"],
                "root_cause_id": case["root_cause_id"],
                "family": case["family"],
                "detector_id": case["detector_id"],
                "detector_status": relevant["status"],
                "prediction": prediction,
                "diagnostic_count": count,
                "diagnostic_ids": [row["diagnostic_id"] for row in relevant["diagnostics"]],
                "coverage": coverage["coverage_counts"],
            }
            predictions.append(prediction_row)
            results.append({
                "identity": identity,
                "prediction": prediction_row,
                "detector_reports": report_by_id,
                "coverage_sidecar": sidecar,
            })
    metrics = summarize_predictions(manifest, predictions)
    output = {
        "schema_version": 1,
        "kind": "ohscanner.independent-holdout-execution.v1",
        "execution_policy": {
            "runs": 1,
            "network": "disabled",
            "git_lazy_fetch": "disabled",
            "detector_tuning_after_freeze": False,
        },
        "holdout_manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "detector_versions": actual_versions,
        "source_identities": sorted(identities, key=lambda row: row["sample_id"]),
        "samples": results,
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    result_sha = save_json(args.output_dir / "results.json", output)
    prediction_sha = save_json(args.output_dir / "predictions.json", predictions)
    metrics_sha = save_json(args.output_dir / "metrics.json", metrics)
    run_manifest = {
        "schema_version": 1,
        "kind": "ohscanner.independent-holdout-run-manifest.v1",
        "artifacts": {
            "results.json": result_sha,
            "predictions.json": prediction_sha,
            "metrics.json": metrics_sha,
        },
        "sample_count": len(predictions),
        "truth_record_count": len(truth_records(manifest)),
    }
    save_json(args.output_dir / "run_manifest.json", run_manifest)
    print(json.dumps(run_manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
