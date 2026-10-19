from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import subprocess
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.path_traversal_detector import CppPathTraversalDetector
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source


def main() -> int:
    parser = argparse.ArgumentParser(description="Direct research replay for the unregistered A-line path detector")
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--git-dir", type=Path, help="read exact bytes from a local bare Git object database")
    parser.add_argument("--commit", help="full commit SHA when --git-dir is used")
    parser.add_argument("--source-path", help="canonical repository path when --git-dir is used")
    parser.add_argument("--parse-status", choices=("auto", "complete", "partial", "failed", "not_run"), default="auto")
    parser.add_argument("--json-out", type=Path, help="write the structured replay result to this path")
    args = parser.parse_args()
    object_identity = None
    if args.git_dir:
        if args.source or not args.commit or not args.source_path:
            parser.error("--git-dir requires --commit and --source-path, and positional source must be omitted")
        if "\\" in args.source_path or args.source_path.startswith("/") or ".." in args.source_path.split("/"):
            parser.error("--source-path must be a canonical repository-relative path")
        git = ["git", "--git-dir=" + str(args.git_dir.resolve())]
        raw = subprocess.run(git + ["show", args.commit + ":" + args.source_path], check=True, stdout=subprocess.PIPE).stdout
        tree = subprocess.run(git + ["rev-parse", args.commit + "^{tree}"], check=True, stdout=subprocess.PIPE, text=True).stdout.strip()
        blob = subprocess.run(git + ["rev-parse", args.commit + ":" + args.source_path], check=True, stdout=subprocess.PIPE, text=True).stdout.strip()
        object_identity = {"commit": args.commit, "tree": tree, "path": args.source_path, "blob": blob}
        source_path = args.source_path
        display_path = "git-object:" + args.commit + ":" + args.source_path
    else:
        if not args.source:
            parser.error("provide a source file or use --git-dir with --commit and --source-path")
        raw = args.source.read_bytes()
        source_path = args.source.name
        display_path = str(args.source.resolve())
    source = raw.decode("utf-8")
    parse_result = parse_source(source, language="cpp") if args.parse_status == "auto" else None
    parse_status = parse_result.parse_status if parse_result else args.parse_status
    parse_issues = tuple(json.dumps(item, sort_keys=True) for item in parse_result.parse_issues) if parse_result else ()
    unit = SourceUnit(source_path, "cpp", source, hashlib.sha256(raw).hexdigest(), parse_status, parse_issues)
    context = ScanContext(ScanRequest(
        "contacts-path-traversal-direct-replay", "fixture/contacts", "2" * 40,
        snapshot_digest((unit,)), "current-component:fixture/contacts", "fixture-no-build",
    ), (unit,))
    started = time.perf_counter()
    run = CppPathTraversalDetector().detect(context, (unit,))
    elapsed = time.perf_counter() - started
    result = json.dumps({
        "source_path": display_path, "source_bytes": len(raw), "git_object_identity": object_identity,
        "source_sha256": unit.sha256, "parse_status": unit.parse_status,
        "parser": "src.parser.ast.parse_source" if parse_result else "explicit-input-status",
        "parse_issue_count": len(parse_issues),
        "detector_id": run.detector_id, "detector_version": run.version,
        "run_status": run.status, "file_outcomes": dict(run.file_outcomes),
        "elapsed_seconds": elapsed,
        "findings": [{"file": f.file, "line": f.line, "column": f.column,
                      "rule_id": f.rule_id, "rule_version": f.rule_version,
                      "symbol": f.symbol, "source_sha256": f.source_sha256,
                      "identity_quality": f.identity_quality} for f in run.findings],
        "limitations": list(run.limitations),
    }, ensure_ascii=False, indent=2)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(result + "\n", encoding="utf-8")
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
