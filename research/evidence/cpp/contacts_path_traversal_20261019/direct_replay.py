from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.path_traversal_detector import CppPathTraversalDetector
from src.ohscanner.fixture import snapshot_digest


def main() -> int:
    parser = argparse.ArgumentParser(description="Direct research replay for the unregistered A-line path detector")
    parser.add_argument("source", type=Path)
    parser.add_argument("--parse-status", choices=("complete", "partial", "failed", "not_run"), default="partial")
    args = parser.parse_args()
    raw = args.source.read_bytes()
    source = raw.decode("utf-8")
    unit = SourceUnit(args.source.name, "cpp", source, hashlib.sha256(raw).hexdigest(), args.parse_status)
    context = ScanContext(ScanRequest(
        "contacts-path-traversal-direct-replay", "fixture/contacts", "2" * 40,
        snapshot_digest((unit,)), "current-component:fixture/contacts", "fixture-no-build",
    ), (unit,))
    started = time.perf_counter()
    run = CppPathTraversalDetector().detect(context, (unit,))
    elapsed = time.perf_counter() - started
    print(json.dumps({
        "source_path": str(args.source.resolve()), "source_bytes": len(raw),
        "source_sha256": unit.sha256, "parse_status": unit.parse_status,
        "detector_id": run.detector_id, "detector_version": run.version,
        "run_status": run.status, "file_outcomes": dict(run.file_outcomes),
        "elapsed_seconds": elapsed,
        "findings": [{"file": f.file, "line": f.line, "column": f.column,
                      "rule_id": f.rule_id, "rule_version": f.rule_version,
                      "symbol": f.symbol, "source_sha256": f.source_sha256,
                      "identity_quality": f.identity_quality} for f in run.findings],
        "limitations": list(run.limitations),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
