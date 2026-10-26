from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import platform
import subprocess
import sys
import types
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKSPACE = ROOT.parent
BASE_COMMIT = "4593a7c9b6977eb81172d01b46cc59daf46f5d45"
DETECTOR_PATH = "src/ohscanner/detectors/cpp/unsafe_memory_call_detector.py"
HELPER_PATH = "src/ohscanner/detectors/cpp/memory_safety.py"
DETECTOR_ID = "ohscanner.cpp.unsafe_memory_call"
RULE_MEMORY = "ohcpp-unsafe-memory-call-candidate-001"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.cpp.unsafe_memory_call_detector import CppUnsafeMemoryCallDetector


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_source(path: str) -> bytes:
    return subprocess.run(
        ["git", "show", f"{BASE_COMMIT}:{path}"],
        cwd=ROOT,
        capture_output=True,
        check=True,
        timeout=10,
    ).stdout


def load_baseline_detector():
    detector_source = git_source(DETECTOR_PATH)
    helper_source = git_source(HELPER_PATH)
    package_name = "src.ohscanner.detectors.cpp_baseline"
    package = types.ModuleType(package_name)
    package.__path__ = [str((ROOT / "src/ohscanner/detectors/cpp").resolve())]
    package.__package__ = package_name
    sys.modules[package_name] = package
    for short_name, path, source in (
        ("memory_safety", HELPER_PATH, helper_source),
        ("unsafe_memory_call_detector", DETECTOR_PATH, detector_source),
    ):
        name = f"{package_name}.{short_name}"
        spec = importlib.util.spec_from_loader(name, loader=None)
        if spec is None:
            raise RuntimeError(f"could not create pinned module {name}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        exec(compile(source.decode("utf-8"), f"{BASE_COMMIT}:{path}", "exec"), module.__dict__)
    cls = sys.modules[f"{package_name}.unsafe_memory_call_detector"].CppUnsafeMemoryCallDetector
    hashes = {
        "detector": sha256(detector_source.replace(b"\r\n", b"\n")),
        "memory_safety_helper": sha256(helper_source.replace(b"\r\n", b"\n")),
    }
    return cls, hashes


def run_file(detector_type, repository: str, commit: str, relative_path: str, data: bytes):
    text = data.decode("utf-8")
    unit = SourceUnit(relative_path, "cpp", text, sha256(data), "complete")
    request = ScanRequest(
        request_id="unsafe-memory-call-replay:" + sha256(data)[:16],
        repository=repository,
        commit=commit,
        snapshot_sha256=snapshot_digest((unit,)),
        target_id="current-component:" + repository,
        profile_id="light-ast",
        provenance="fixture",
    )
    run = detector_type().detect(ScanContext(request, (unit,), {}), (unit,))
    findings = []
    for finding in run.findings:
        if finding.rule_id != RULE_MEMORY:
            continue
        findings.append({
            "line": finding.line,
            "column": finding.column,
            "rule_id": finding.rule_id,
            "symbol": finding.symbol,
            "message": finding.message,
        })
    outcome = dict(run.file_outcomes).get(relative_path, "missing")
    return findings, outcome, list(run.limitations)


def canonical(items):
    return sorted((x["line"], x["column"], x["rule_id"], x["symbol"], x["message"]) for x in items)


def main() -> int:
    parser = argparse.ArgumentParser(description="Pinned replay of unsafe-memory-call observations after shared argument splitting change")
    parser.add_argument("--scan-root", type=Path, default=WORKSPACE / "openharmony-abcd-full-scan-20261018-final")
    parser.add_argument("--source-root", type=Path, default=WORKSPACE / "openharmony")
    parser.add_argument("--output", type=Path, default=ROOT / "research/evidence/cpp/a_unsafe_memory_review_20261018/unsafe_memory_call_argument_split_replay_20261019.json")
    args = parser.parse_args()

    csv_path = args.scan_root / "candidate_results.csv"
    projects_path = args.scan_root / "project_summary.csv"
    config_path = args.scan_root / "run_config.json"
    rows_by_repo = defaultdict(list)
    with csv_path.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            if row.get("rule_id") == RULE_MEMORY:
                rows_by_repo[row["repository"]].append(row)
    projects = {}
    with projects_path.open(encoding="utf-8-sig", newline="") as source:
        projects = {row["repository"]: row for row in csv.DictReader(source)}
    config = json.loads(config_path.read_text(encoding="utf-8"))

    baseline_type, baseline_hashes = load_baseline_detector()
    current_source = (ROOT / DETECTOR_PATH).read_bytes()
    current_hash = sha256(current_source.replace(b"\r\n", b"\n"))
    current_helper_source = (ROOT / HELPER_PATH).read_bytes()
    current_helper_hash = sha256(current_helper_source.replace(b"\r\n", b"\n"))
    expected_by_file = defaultdict(list)
    source_hash_by_file = {}
    inputs = []
    for repository, rows in sorted(rows_by_repo.items()):
        project = projects[repository]
        result_path = Path(rows[0]["result_path"].replace("/mnt/d/openHarmonyScanner/", "D:/openHarmonyScanner/"))
        report = json.loads(result_path.read_text(encoding="utf-8"))
        detector_run = next(item for item in report["detector_runs"] if item["tool"] == DETECTOR_ID)
        diagnostics = {item["diagnostic_id"]: item for item in detector_run["diagnostics"]}
        seen = set()
        for row in rows:
            diagnostic = diagnostics[row["diagnostic_id"]]
            if diagnostic["message"] != row["message"] or int(diagnostic["line"]) != int(row["line"]):
                raise ValueError(f"candidate row/result mismatch: {row['diagnostic_id']}")
            key = (repository, row["file"])
            digest = diagnostic.get("source_sha256")
            if not digest or (key in source_hash_by_file and source_hash_by_file[key] != digest):
                raise ValueError(f"source hash absent or inconsistent: {repository}:{row['file']}")
            source_hash_by_file[key] = digest
            expected_by_file[key].append({
                "line": int(diagnostic["line"]),
                "column": diagnostic.get("column"),
                "rule_id": diagnostic["rule_id"],
                "symbol": diagnostic.get("symbol"),
                "message": diagnostic["message"],
            })
            if key in seen:
                continue
            seen.add(key)
            source_path = args.source_root / project["project_path"] / Path(row["file"])
            data = source_path.read_bytes()
            if sha256(data) != digest:
                raise ValueError(f"source hash mismatch: {repository}:{row['file']}")
            inputs.append((repository, project["manifest_commit"], row["file"], data, digest))

    before_count = after_count = 0
    outcome_counts = Counter()
    changes = Counter()
    examples = {"removed": [], "added": [], "changed": []}
    signature_unknown_files = []
    for repository, commit, relative_path, data, digest in inputs:
        before, before_outcome, _ = run_file(baseline_type, repository, commit, relative_path, data)
        after, after_outcome, limitations = run_file(CppUnsafeMemoryCallDetector, repository, commit, relative_path, data)
        outcome_counts[after_outcome] += 1
        if canonical(before) != canonical(expected_by_file[(repository, relative_path)]):
            raise ValueError(f"pinned baseline findings did not reproduce: {repository}:{relative_path}")
        if any("format_call_signature_unknown" in item for item in limitations):
            signature_unknown_files.append({"repository": repository, "file": relative_path, "source_sha256": digest})
        before_count += len(before)
        after_count += len(after)
        before_sites = {(item["line"], item["column"]): item for item in before}
        after_sites = {(item["line"], item["column"]): item for item in after}
        for site in before_sites.keys() - after_sites.keys():
            changes["removed"] += 1
            if len(examples["removed"]) < 25:
                examples["removed"].append({"repository": repository, "file": relative_path, "source_sha256": digest, "before": before_sites[site]})
        for site in after_sites.keys() - before_sites.keys():
            changes["added"] += 1
            if len(examples["added"]) < 25:
                examples["added"].append({"repository": repository, "file": relative_path, "source_sha256": digest, "after": after_sites[site]})
        for site in before_sites.keys() & after_sites.keys():
            if before_sites[site] != after_sites[site]:
                changes["changed"] += 1
                if len(examples["changed"]) < 25:
                    examples["changed"].append({"repository": repository, "file": relative_path, "source_sha256": digest, "before": before_sites[site], "after": after_sites[site]})

    if before_count != sum(len(rows) for rows in rows_by_repo.values()):
        raise ValueError("pinned baseline count did not reproduce candidate CSV")
    artifact = {
        "schema_version": "ohscanner.a-unsafe-memory-call-shared-argument-replay-v1",
        "source_run_signature": config["run_signature"],
        "scanner_commit": config["scanner_commit"],
        "candidate_results_sha256": sha256(csv_path.read_bytes()),
        "base_commit": BASE_COMMIT,
        "scope": "Only the existing unsafe-memory-call rule observations are replayed; this is a 235-file candidate subset, not a full scan.",
        "detector": {
            "id": DETECTOR_ID,
            "rule_id": RULE_MEMORY,
            "before_version": baseline_type.version,
            "after_version": CppUnsafeMemoryCallDetector.version,
            "before_dependency_source_sha256": baseline_hashes,
            "after_detector_source_sha256": current_hash,
            "after_dependency_source_sha256": {
                "detector": current_hash,
                "memory_safety_helper": current_helper_hash,
            },
        },
        "source_identity": {"candidate_rows": before_count, "unique_source_files": len(inputs), "source_hashes_matched": len(inputs)},
        "before": {"candidate_rows_reproduced": before_count},
        "after": {"candidate_rows": after_count},
        "after_file_outcomes": dict(sorted(outcome_counts.items())),
        "after_signature_unknown_files": signature_unknown_files,
        "changes": dict(sorted(changes.items())),
        "examples": examples,
        "tooling": {"python": platform.python_version(), "mode": "in-process replay with pinned detector and memory_safety helper; no CFG or product-build claim"},
        "interpretation": "This validates the effect of the shared call-argument splitter on the pinned unsafe-memory-call observation subset. It does not label findings as true/false positives or replace independent review.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "before": before_count, "after": after_count, "files": len(inputs), "source_hashes_matched": len(inputs), "changes": dict(changes), "outcomes": dict(outcome_counts), "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
