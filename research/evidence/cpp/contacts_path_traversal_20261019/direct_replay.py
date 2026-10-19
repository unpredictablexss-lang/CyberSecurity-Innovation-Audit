from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.path_traversal_detector import CppPathTraversalDetector
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source


def main() -> int:
    parser = argparse.ArgumentParser(description="Direct research replay for the unregistered A-line path detector")
    parser.add_argument("source", type=Path, nargs="?", help="local source file; omit when reading a pinned Git object")
    parser.add_argument("--git-dir", type=Path, help="bare or normal Git repository object database")
    parser.add_argument("--commit", help="commit to bind the source path to")
    parser.add_argument("--source-path", help="repository-relative path inside --commit")
    parser.add_argument("--parse-status", choices=("auto", "complete", "partial", "failed", "not_run"), default="auto")
    parser.add_argument("--json-out", type=Path, help="optional path for the structured replay result")
    args = parser.parse_args()

    object_identity = None
    if args.git_dir or args.commit or args.source_path:
        if args.source is not None or not (args.git_dir and args.commit and args.source_path):
            parser.error("use either SOURCE or all of --git-dir, --commit, and --source-path")
        git_prefix = ["git", f"--git-dir={args.git_dir}"]
        try:
            tree = subprocess.check_output(git_prefix + ["rev-parse", f"{args.commit}^{{tree}}"], text=True).strip()
            blob = subprocess.check_output(git_prefix + ["rev-parse", f"{args.commit}:{args.source_path}"], text=True).strip()
            raw = subprocess.check_output(git_prefix + ["cat-file", "blob", blob])
        except subprocess.CalledProcessError as exc:
            parser.error(f"cannot read pinned Git source object: {exc}")
        source_label = f"git-object:{args.commit}:{args.source_path}"
        object_identity = {"git_dir": str(args.git_dir), "commit": args.commit, "tree": tree,
                           "path": args.source_path, "blob": blob}
    else:
        if args.source is None:
            parser.error("provide SOURCE or a pinned Git object")
        raw = args.source.read_bytes()
        source_label = str(args.source.resolve())

    source = raw.decode("utf-8")
    parsed = parse_source(source, language="cpp")
    parse_status = parsed.parse_status if args.parse_status == "auto" else args.parse_status
    source_sha256 = hashlib.sha256(raw).hexdigest()
    file_name = (args.source_path or args.source.name).replace("\\", "/")
    unit = SourceUnit(file_name, "cpp", source, source_sha256, parse_status)
    context = ScanContext(ScanRequest(
        "contacts-path-traversal-direct-replay", "fixture/contacts", "2" * 40,
        snapshot_digest((unit,)), "current-component:fixture/contacts", "fixture-no-build",
    ), (unit,))
    started = time.perf_counter()
    run = CppPathTraversalDetector().detect(context, (unit,))
    elapsed = time.perf_counter() - started
    result = {
        "source_path": source_label, "source_bytes": len(raw),
        "source_sha256": unit.sha256, "source_identity": object_identity, "parse_status": unit.parse_status,
        "parser": "src.parser.ast.parse_source", "parse_issue_count": len(parsed.parse_issues),
        "detector_id": run.detector_id, "detector_version": run.version,
        "run_status": run.status, "file_outcomes": dict(run.file_outcomes),
        "elapsed_seconds": elapsed,
        "findings": [{"file": f.file, "line": f.line, "column": f.column,
                      "rule_id": f.rule_id, "rule_version": f.rule_version,
                      "symbol": f.symbol, "source_sha256": f.source_sha256,
                      "identity_quality": f.identity_quality} for f in run.findings],
        "limitations": list(run.limitations),
    }
    output = json.dumps(result, ensure_ascii=False, indent=2)
    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(output + "\n", encoding="utf-8")
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
