#!/usr/bin/env python3
"""Reverify frozen scanner bytes and pinned Ark Runtime source identities; never runs detector predictions."""
import argparse
import csv
import hashlib
import importlib.metadata
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
ADMIN = ROOT / "admin"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scanner-repo", required=True, help="Local Git checkout containing the frozen scanner commit")
    ap.add_argument("--output", default=str(ADMIN / "freeze_verification.json"))
    args = ap.parse_args()
    lock = json.loads((ADMIN / "frozen_detector.json").read_text(encoding="utf-8"))
    manifest = list(csv.DictReader((ADMIN / "holdout_source_manifest.csv").open(encoding="utf-8-sig", newline="")))
    run = json.loads((ADMIN / "blind_run_summary.json").read_text(encoding="utf-8"))
    errors, source_results = [], []
    commit = lock["scanner_commit"]
    tree = git(args.scanner_repo, "show", "-s", "--format=%T", commit).decode().strip()
    if tree != lock["scanner_tree"]:
        errors.append("scanner commit tree mismatch")
    archive = git(args.scanner_repo, "archive", "--format=tar", commit)
    with tempfile.TemporaryDirectory(prefix="ark-holdout-freeze-") as temp:
        archive_root = Path(temp)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as tf:
            tf.extractall(archive_root, filter="data")
        sys.path.insert(0, str(archive_root))
        from src.ohscanner.detectors.ark_runtime.model import RuntimeTypeModel, VERSION
        if VERSION != lock["detector_version"]:
            errors.append("detector version mismatch")
        if RuntimeTypeModel().digest != lock["model_digest_sha256"]:
            errors.append("model digest mismatch")
        implementation_results = {}
        for rel, expected in lock["implementation_sha256"].items():
            actual = sha256((archive_root / rel).read_bytes())
            implementation_results[rel] = {"expected": expected, "actual": actual, "match": actual == expected}
            if actual != expected:
                errors.append("implementation hash mismatch: " + rel)
        parser_path = archive_root / "src/parser/ast.py"
        parser_sha = sha256(parser_path.read_bytes())
        if parser_sha != lock["parser_ast_sha256"]:
            errors.append("parser implementation hash mismatch")
        from src.parser.ast import parse_source
        tree_sitter_version = importlib.metadata.version("tree-sitter")
        tree_sitter_cpp_version = importlib.metadata.version("tree-sitter-cpp")
        for row in manifest:
            url = f"https://raw.githubusercontent.com/{row['repository']}/{row['commit']}/{row['path']}"
            with urlopen(url, timeout=30) as response:
                content = response.read()
            source_sha = sha256(content)
            blob_sha = hashlib.sha1(b"blob " + str(len(content)).encode("ascii") + b"\0" + content).hexdigest()
            parsed = parse_source(content.decode("utf-8", "strict"), "cpp")
            checks = {
                "bytes_match": len(content) == int(row["bytes"]),
                "source_sha256_match": source_sha == row["source_sha256"],
                "git_blob_sha1_match": blob_sha == row["blob"],
                "parser_status_match": parsed.parse_status == row["parse_status"],
                "parser_issue_count_match": len(parsed.parse_issues) == int(row["parse_issue_count"]),
            }
            if not all(checks.values()):
                errors.append("source identity or parse mismatch: " + row["sample_id"])
            source_results.append({"sample_id": row["sample_id"], "commit": row["commit"], "path": row["path"],
                                   "source_sha256": source_sha, "git_blob_sha1": blob_sha,
                                   "parser_status": parsed.parse_status, "parser_issue_count": len(parsed.parse_issues),
                                   "checks": checks})
    coverage = run.get("detector_coverage_status_counts", {})
    escrow_path = Path(args.scanner_repo) / run.get("raw_prediction_escrow_path", "")
    escrow_presence = "present_not_read" if escrow_path.is_file() else "missing_at_recorded_path"
    if run.get("labels_frozen_before_run") is not False:
        errors.append("blind run summary label-freeze state changed unexpectedly")
    if run.get("sample_count") != len(manifest):
        errors.append("blind-run sample count differs from manifest")
    result = {
        "assessment_id": lock["assessment_id"],
        "verification_scope": "frozen scanner implementation/model/parser and source identity/parser states only; no detector prediction run",
        "scanner": {"commit": commit, "tree": tree, "version": VERSION, "model_digest": RuntimeTypeModel().digest,
                    "model_digest_match": RuntimeTypeModel().digest == lock["model_digest_sha256"],
                    "implementation_file_count": len(implementation_results), "implementation_files": implementation_results,
                    "parser_ast_sha256": parser_sha, "parser_ast_match": parser_sha == lock["parser_ast_sha256"]},
        "parser_dependencies": {"tree_sitter": tree_sitter_version, "tree_sitter_cpp": tree_sitter_cpp_version},
        "sample_count": len(manifest), "source_results": source_results,
        "recorded_blind_replay": {"coverage_status_counts": coverage,
                                   "labels_frozen_before_run": run.get("labels_frozen_before_run"),
                                   "metrics_estimable": False,
                                   "prediction_escrow_path": str(escrow_path),
                                   "prediction_escrow_presence": escrow_presence,
                                   "prediction_escrow_contents_read": False},
        "errors": errors,
        "status": "verified_freeze_and_source_identities" if not errors else "verification_failed",
    }
    Path(args.output).write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "sample_count": len(manifest),
                      "source_matches": sum(all(x["checks"].values()) for x in source_results),
                      "errors": errors, "output": str(Path(args.output).resolve())}, ensure_ascii=False))
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
