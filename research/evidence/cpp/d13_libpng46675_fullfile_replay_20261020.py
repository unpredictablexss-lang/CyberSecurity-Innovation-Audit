"""Replay current resource-lifetime detector on exact libpng 46675 source bytes.

Inputs remain in an external read-only source cache. This records full-file
parsing and detector output; function-fragment results are in the paired JSON
produced by d12_libpng_function_fragments_20261020.py.
"""
from __future__ import annotations

from dataclasses import asdict
from hashlib import sha256
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.resource_lifetime_detector import CppResourceLifetimeDetector
from src.parser.ast import parse_source

SOURCES = {
    "vulnerable": {
        "path": Path("D:/openHarmonyScanner/tmp/libpng-ghsa-qvg3-source-20261019/vulnerable-1.6.55/pngrutil.c"),
        "commit": "c3e304954a9cfd154bc0dfbfea2b01cd61d6546d",
        "blob": "a4eda54c8cb3d36cf1651dba159067b65030e3aa",
        "sha256": "b328fb05352226866b1e44c8cdd3e03df35413f1f38f4d81ba51afe4f2333a5e",
    },
    "fixed": {
        "path": Path("D:/openHarmonyScanner/tmp/libpng-d13-fixed-source-20261020/pngrutil.c"),
        "commit": "aa77ef38c17ab2fc1b41bec09fb973c6a386641d",
        "blob": "482f0ae8dfd4793e7a4f266b609bc5c8b9e9334a",
        "sha256": "a1d62bc61c118b225c60549ea8de3065ae84642af56dd3776bf4692fb0f6aa5e",
    },
}


def scan(variant: str, source: dict) -> dict:
    raw = source["path"].read_bytes()
    digest = sha256(raw).hexdigest()
    if digest != source["sha256"]:
        raise ValueError(f"SHA-256 mismatch for {variant}: {digest}")
    text = raw.decode("utf-8")
    parsed = parse_source(text, language="c")
    unit = SourceUnit(
        path=f"{variant}/pngrutil.c", language="c", text=text, sha256=digest,
        parse_status=parsed.parse_status,
        parse_issues=tuple(json.dumps(issue, sort_keys=True) for issue in parsed.parse_issues),
    )
    request = ScanRequest(
        request_id=f"d13:46675:{variant}:pngrutil.c",
        repository="pnggroup/libpng", commit=source["commit"], snapshot_sha256=digest,
        target_id="current-component:pnggroup/libpng", profile_id="light-ast",
        provenance="fixture",
    )
    detector = CppResourceLifetimeDetector()
    started = time.perf_counter()
    result = detector.detect(ScanContext(request=request, units=(unit,)), (unit,))
    elapsed = time.perf_counter() - started
    return {
        "variant": variant, "source_path_external": str(source["path"]),
        "commit": source["commit"], "tree": None,
        "blob": source["blob"], "sha256": digest, "bytes": len(raw),
        "parse_status": parsed.parse_status, "parse_issue_count": len(parsed.parse_issues),
        "parse_issues": [asdict(issue) if hasattr(issue, "__dataclass_fields__") else str(issue)
                         for issue in parsed.parse_issues],
        "detector": detector.detector_id, "detector_version": detector.version,
        "status": result.status, "analyzed_files": list(result.analyzed_files),
        "finding_count": len(result.findings),
        "findings": [asdict(item) for item in result.findings],
        "limitations": list(result.limitations), "elapsed_seconds": elapsed,
        "interpretation": "Exact file-byte detector replay; partial parse keeps zero findings inconclusive.",
    }


def main() -> None:
    result = {
        "schema_version": 1,
        "experiment": "exact_source_fullfile_resource_lifetime_replay",
        "baseline": "9e5735e33ef801d0d01beca43d7d5ced40a56d50",
        "source_repository": "pnggroup/libpng",
        "source_refs": {
            "vulnerable": SOURCES["vulnerable"]["commit"],
            "fixed": SOURCES["fixed"]["commit"],
            "official_fixed_commit_parent": "4eeb825 (verified through GitHub commit metadata)",
            "fixed_commit_tree": None,
            "tree_limitation": "GitHub fetch-file and fetch-commit metadata confirmed commit/file bytes but did not return commit tree; direct git clone failed with github.com:443 connection refusal/time-out.",
        },
        "runs": [scan(name, source) for name, source in SOURCES.items()],
        "limitations": [
            "The exact official source commit and file blob/SHA are bound, but the official commit tree ID could not be retrieved in this environment.",
            "The full-file replay invokes the current first-party detector directly on the exact source bytes because the upstream Git object graph could not be fetched; it is not a run_fixed_commit_scan CLI invocation.",
            "Full translation units parse partial; no findings are inconclusive, not a safe/fixed conclusion.",
            "The paired function-fragment replay preserves original line positions but does not prove cross-function ownership, call order, trigger, or product reachability.",
        ],
    }
    out = ROOT / "research/evidence/cpp/d13_libpng46675_fullfile_replay_20261020.json"
    out.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(out), "runs": [
        {"variant": run["variant"], "sha256": run["sha256"], "parse_status": run["parse_status"],
         "parse_issue_count": run["parse_issue_count"], "status": run["status"],
         "finding_count": run["finding_count"], "elapsed_seconds": run["elapsed_seconds"]}
        for run in result["runs"]]}, indent=2))


if __name__ == "__main__":
    main()
