"""Replay archived OpenHarmony disclosure patch pairs with the first-party IPC detector.

This is a research replay over extracted patch files. It does not prove the archive
matches a Git object, does not build the product, and does not count as exploit
validation. By default test/mock/sample trees are excluded using the production
scope segment rules in the scanner.
"""
import argparse
import hashlib
import json
from pathlib import Path

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source

SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}
PRODUCTION_EXCLUDES = {
    "test", "tests", "unittest", "unittests", "fuzztest", "fuzz",
    "mock", "mocks", "sample", "samples", "example", "examples",
    "benchmark", "benchmarks", "vendor", "vendors", "third_party",
    "third-party", "external",
}


def replay_side(pair_dir, side, repository, commit, include_tests):
    root = pair_dir / side
    units, asts, files = [], {}, []
    for source in sorted(root.rglob("*")):
        if not source.is_file() or source.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        rel = source.relative_to(root).as_posix()
        path_parts = Path(rel).parts[:-1]
        if not include_tests and any(part.lower() in PRODUCTION_EXCLUDES for part in path_parts):
            continue
        raw = source.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        language = "c" if source.suffix.lower() == ".c" else "cpp"
        parsed = parse_source(text, language=language)
        unit = SourceUnit(rel, language, text, hashlib.sha256(raw).hexdigest(),
                          parsed.parse_status)
        units.append(unit)
        asts[rel] = parsed.to_dict()
        files.append({
            "path": rel,
            "source_sha256": unit.sha256,
            "parse_status": unit.parse_status,
        })
    if not units:
        return {"status": "not_run", "files": [], "findings": []}
    request = ScanRequest(
        pair_dir.name, repository, commit, snapshot_digest(tuple(units)),
        "current-component:" + repository,
    )
    context = ScanContext(request, tuple(units), {"ast": asts})
    run = IpcInterfaceDetector().detect(context, tuple(units))
    findings = [{
        "file": finding.file,
        "line": finding.line,
        "rule_id": finding.rule_id,
        "symbol": finding.symbol,
        "message": finding.message,
        "evidence_obligations": [
            {"kind": obligation.kind, "description": obligation.description}
            for obligation in finding.evidence_obligations
        ],
    } for finding in run.findings]
    return {
        "status": run.status,
        "files": files,
        "counts": {
            "complete": sum(item.parse_status == "complete" for item in units),
            "partial": sum(item.parse_status == "partial" for item in units),
            "failed": sum(item.parse_status == "failed" for item in units),
        },
        "finding_count": len(findings),
        "findings": findings,
        "limitations": list(run.limitations),
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pairs-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--include-tests", action="store_true")
    args = parser.parse_args()
    results = []
    for pair_dir in sorted(path for path in args.pairs_root.iterdir() if path.is_dir()):
        lineage = pair_dir / "lineage.json"
        if not lineage.is_file():
            continue
        metadata = json.loads(lineage.read_text(encoding="utf-8"))
        repository = metadata.get("repository")
        if not repository:
            continue
        results.append({
            "sample_id": metadata.get("sample_id", pair_dir.name),
            "repository": repository,
            "lineage_metadata": metadata,
            "lineage_sha256": hashlib.sha256(lineage.read_bytes()).hexdigest(),
            "input_kind": "archived extracted patch files; Git object binding not checked",
            "vulnerable": replay_side(
                pair_dir, "vulnerable", repository,
                metadata.get("vulnerable_commit", "unknown"), args.include_tests,
            ),
            "fixed": replay_side(
                pair_dir, "fixed", repository,
                metadata.get("fixed_commit", "unknown"), args.include_tests,
            ),
        })
    result = {
        "schema_version": 1,
        "experiment": "first_party_ipc_disclosure_pair_replay",
        "detector_id": "ohscanner.interface.ipc",
        "detector_version": IpcInterfaceDetector.version,
        "model_version": IpcInterfaceDetector.model_version,
        "scope_mode": "include_tests" if args.include_tests else "production_path_segment_filter",
        "product_or_exploit_validation": False,
        "pair_count": len(results),
        "pairs": results,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n",
                           encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "pair_count": len(results),
        "detector_version": result["detector_version"],
        "model_version": result["model_version"],
        "scope_mode": result["scope_mode"],
    }, indent=2))


if __name__ == "__main__":
    main()
