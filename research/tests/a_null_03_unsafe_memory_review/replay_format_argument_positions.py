from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import platform
import re
import subprocess
import sys
import types
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKSPACE = ROOT.parent
BASE_COMMIT = "4593a7c9b6977eb81172d01b46cc59daf46f5d45"
BASE_DETECTOR_SHA256 = "cd4825a5387c5fd2415a7b5ac8d6fc7989a2222bd7f699507e63ad4c4b443e52"
DETECTOR_PATH = "src/ohscanner/detectors/cpp/unsafe_memory_call_detector.py"
HELPER_PATH = "src/ohscanner/detectors/cpp/memory_safety.py"
FORMAT_RULE = "ohcpp-format-string-candidate-002"
CALLEE_RE = __import__("re").compile(r"Candidate only: `([^`]+)` receives a non-literal format expression `([^`]+)`\.")

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.cpp.unsafe_memory_call_detector import CppUnsafeMemoryCallDetector


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expression_shape(expression: str) -> str:
    value = expression.strip()
    if re.fullmatch(r"[A-Za-z_]\w*", value):
        return "identifier"
    if value.startswith(('"', "'")):
        return "literal_prefix_with_trailing_tokens"
    if "?" in value:
        return "conditional_or_ternary"
    if re.search(r"\b[A-Za-z_]\w*\s*\(", value):
        return "call_or_macro_invocation"
    return "other_compound_expression"


def load_baseline_detector():
    def source_at(path: str) -> bytes:
        return subprocess.run(
            ["git", "show", f"{BASE_COMMIT}:{path}"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout

    helper_path = "src/ohscanner/detectors/cpp/memory_safety.py"
    detector_source = source_at(DETECTOR_PATH)
    helper_source = source_at(helper_path)
    detector_sha = sha256(detector_source.replace(b"\r\n", b"\n"))
    helper_sha = sha256(helper_source.replace(b"\r\n", b"\n"))
    if detector_sha != BASE_DETECTOR_SHA256:
        raise ValueError(f"pinned baseline detector hash mismatch: {detector_sha}")

    # Give the baseline modules their own package namespace so relative imports
    # cannot silently bind to the modified worktree helper.
    package_name = "src.ohscanner.detectors.cpp_baseline"
    package = types.ModuleType(package_name)
    package.__path__ = [str((ROOT / "src/ohscanner/detectors/cpp").resolve())]
    package.__package__ = package_name
    sys.modules[package_name] = package
    for short_name, path, source in (
        ("memory_safety", helper_path, helper_source),
        ("unsafe_memory_call_detector", DETECTOR_PATH, detector_source),
    ):
        name = f"{package_name}.{short_name}"
        spec = importlib.util.spec_from_loader(name, loader=None)
        if spec is None:
            raise RuntimeError(f"could not create pinned baseline module: {name}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        exec(compile(source.decode("utf-8"), f"{BASE_COMMIT}:{path}", "exec"), module.__dict__)
    return sys.modules[f"{package_name}.unsafe_memory_call_detector"].CppUnsafeMemoryCallDetector, {
        "detector": detector_sha,
        "memory_safety_helper": helper_sha,
    }


def run_one(detector_type, repository: str, commit: str, relative_path: str, data: bytes) -> tuple[list[dict], str, list[str]]:
    text = data.decode("utf-8")
    unit = SourceUnit(relative_path, "cpp", text, sha256(data), "complete")
    request = ScanRequest(
        request_id="format-index:" + sha256(data)[:16],
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
        if finding.rule_id != FORMAT_RULE:
            continue
        match = CALLEE_RE.search(finding.message)
        if not match or match.group(1) not in {"fprintf", "vfprintf"}:
            continue
        findings.append({
            "line": finding.line,
            "column": finding.column,
            "rule_id": finding.rule_id,
            "symbol": finding.symbol,
            "message": finding.message,
        })
    return findings, dict(run.file_outcomes).get(relative_path, "missing"), list(run.limitations)


def main() -> int:
    parser = argparse.ArgumentParser(description="Pinned replay of existing fprintf/vfprintf format candidates")
    parser.add_argument("--scan-root", type=Path, default=WORKSPACE / "openharmony-abcd-full-scan-20261018-final")
    parser.add_argument("--source-root", type=Path, default=WORKSPACE / "openharmony")
    parser.add_argument("--output", type=Path, default=ROOT / "research/evidence/cpp/a_unsafe_memory_review_20261018/format_argument_positions_before_after_20261019.json")
    args = parser.parse_args()

    results_path = args.scan_root / "candidate_results.csv"
    project_path = args.scan_root / "project_summary.csv"
    config_path = args.scan_root / "run_config.json"
    result_rows: dict[str, list[dict]] = defaultdict(list)
    with results_path.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            if row.get("rule_id") != FORMAT_RULE:
                continue
            match = CALLEE_RE.search(row.get("message", ""))
            if match and match.group(1) in {"fprintf", "vfprintf"}:
                result_rows[row["repository"]].append(row)

    projects = {}
    with project_path.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            projects[row["repository"]] = row
    run_config = json.loads(config_path.read_text(encoding="utf-8"))
    baseline, baseline_dependency_hashes = load_baseline_detector()
    current_source = (ROOT / DETECTOR_PATH).read_bytes()
    current_sha = sha256(current_source.replace(b"\r\n", b"\n"))
    current_helper_source = (ROOT / HELPER_PATH).read_bytes()
    current_helper_sha = sha256(current_helper_source.replace(b"\r\n", b"\n"))
    inputs = []
    expected_by_file: dict[tuple[str, str], list[dict]] = defaultdict(list)
    expected_source_hash: dict[tuple[str, str], str] = {}
    seen_paths = set()
    for repository, rows in sorted(result_rows.items()):
        project = projects[repository]
        result_file = Path(rows[0]["result_path"].replace("/mnt/d/openHarmonyScanner/", "D:/openHarmonyScanner/"))
        result = json.loads(result_file.read_text(encoding="utf-8"))
        detector_run = next(item for item in result["detector_runs"] if item["tool"] == "ohscanner.cpp.unsafe_memory_call")
        diagnostics = {item["diagnostic_id"]: item for item in detector_run["diagnostics"]}
        for row in rows:
            key = (repository, row["file"])
            diagnostic = diagnostics[row["diagnostic_id"]]
            if diagnostic["message"] != row["message"] or int(diagnostic["line"]) != int(row["line"]):
                raise ValueError(f"candidate row/diagnostic mismatch: {row['diagnostic_id']}")
            diagnostic_source_sha = diagnostic.get("source_sha256")
            if not diagnostic_source_sha:
                raise ValueError(f"missing diagnostic source hash: {row['diagnostic_id']}")
            if key in expected_source_hash and expected_source_hash[key] != diagnostic_source_sha:
                raise ValueError(f"source hash varies within one source file: {repository}:{row['file']}")
            expected_source_hash[key] = diagnostic_source_sha
            expected_by_file[key].append({
                "line": int(diagnostic["line"]),
                "column": diagnostic.get("column"),
                "rule_id": diagnostic["rule_id"],
                "symbol": diagnostic.get("symbol"),
                "message": diagnostic["message"],
            })
            if key in seen_paths:
                continue
            seen_paths.add(key)
            source_file = args.source_root / project["project_path"] / Path(row["file"])
            data = source_file.read_bytes()
            source_sha = expected_source_hash[key]
            if sha256(data) != source_sha:
                raise ValueError(f"source hash mismatch: {repository}:{row['file']}")
            inputs.append((repository, project["manifest_commit"], row["file"], data, source_sha, rows[0]["result_path"]))

    before_counts = Counter()
    after_counts = Counter()
    legacy_prefix_suppressed = Counter()
    legacy_filtered_after_counts = Counter()
    legacy_prefix_examples = []
    change_counts = Counter()
    examples = {"removed": [], "changed": [], "added": []}
    reproduced_rows = 0
    after_outcomes = Counter()
    after_signature_unknown_files = []
    after_candidate_inventory = []
    after_shape_counts = Counter()
    after_shape_by_callee = Counter()
    for input_index, (repository, commit, relative_path, data, source_sha, result_path) in enumerate(inputs, 1):
        print(f"starting {input_index}/{len(inputs)} {repository}:{relative_path}", flush=True)
        before, before_outcome, _ = run_one(baseline, repository, commit, relative_path, data)
        after, after_outcome, after_limitations = run_one(CppUnsafeMemoryCallDetector, repository, commit, relative_path, data)
        after_outcomes[after_outcome] += 1
        if any("format_call_signature_unknown" in item for item in after_limitations):
            after_signature_unknown_files.append({"repository": repository, "file": relative_path, "source_sha256": source_sha})
        if before_outcome not in ("complete", "missing"):
            raise ValueError(f"pinned baseline produced unexpected per-file outcome {before_outcome}: {repository}:{relative_path}")
        canonical = lambda values: sorted((item["line"], item["column"], item["rule_id"], item["symbol"], item["message"]) for item in values)
        if canonical(before) != canonical(expected_by_file[(repository, relative_path)]):
            raise ValueError(f"pinned baseline does not reproduce original findings: {repository}:{relative_path}")
        before_by_site = {(item["line"], item["column"]): item for item in before}
        after_by_site = {(item["line"], item["column"]): item for item in after}
        for item in before:
            match = CALLEE_RE.search(item["message"])
            callee = match.group(1) if match else "unknown"
            before_counts[callee] += 1
        for item in after:
            match = CALLEE_RE.search(item["message"])
            callee = match.group(1) if match else "unknown"
            after_counts[callee] += 1
            shape = expression_shape(item["symbol"])
            after_shape_counts[shape] += 1
            after_shape_by_callee[(callee, shape)] += 1
            after_candidate_inventory.append({
                "repository": repository,
                "file": relative_path,
                "source_sha256": source_sha,
                "line": item["line"],
                "column": item["column"],
                "callee": callee,
                "expression": item["symbol"],
                "expression_shape": shape,
                "message": item["message"],
            })
            if item["symbol"].lstrip().startswith(('"', "'")):
                legacy_prefix_suppressed[callee] += 1
                if len(legacy_prefix_examples) < 20:
                    legacy_prefix_examples.append({
                        "repository": repository,
                        "file": relative_path,
                        "source_sha256": source_sha,
                        "line": item["line"],
                        "column": item["column"],
                        "callee": callee,
                        "expression": item["symbol"],
                    })
            else:
                legacy_filtered_after_counts[callee] += 1
        for site in before_by_site.keys() - after_by_site.keys():
            change_counts["removed"] += 1
            if len(examples["removed"]) < 20:
                examples["removed"].append({"repository": repository, "file": relative_path, "source_sha256": source_sha, "before": before_by_site[site]})
        for site in after_by_site.keys() - before_by_site.keys():
            change_counts["added"] += 1
            if len(examples["added"]) < 20:
                examples["added"].append({"repository": repository, "file": relative_path, "source_sha256": source_sha, "after": after_by_site[site]})
        for site in before_by_site.keys() & after_by_site.keys():
            if before_by_site[site]["symbol"] != after_by_site[site]["symbol"]:
                change_counts["corrected_argument_expression"] += 1
                if len(examples["changed"]) < 20:
                    examples["changed"].append({"repository": repository, "file": relative_path, "source_sha256": source_sha, "before": before_by_site[site], "after": after_by_site[site]})
        if input_index % 10 == 0 or input_index == len(inputs):
            print(f"replayed {input_index}/{len(inputs)} files", flush=True)

    all_candidate_count = sum(len(rows) for rows in result_rows.values())
    # Each baseline replay was compared field-by-field with the original rows.
    reproduced_rows = sum(before_counts.values())
    if reproduced_rows != all_candidate_count:
        raise ValueError(f"baseline replay rows {reproduced_rows} do not match pinned observations {all_candidate_count}")

    artifact = {
        "schema_version": "ohscanner.a-unsafe-format-argument-index-replay-v1",
        "source_run_signature": run_config["run_signature"],
        "scanner_commit": run_config["scanner_commit"],
        "candidate_results_sha256": sha256(results_path.read_bytes()),
        "base_commit": BASE_COMMIT,
        "comparison_scope": "All pinned format-string observations whose callee is fprintf or vfprintf, replayed on source-hash-matched files from the original 2026-10-18 final scan. Other detector families and source files without these prior observations are outside this subset.",
        "detector": {
            "id": "ohscanner.cpp.unsafe_memory_call",
            "before_version": baseline.version,
            "after_version": CppUnsafeMemoryCallDetector.version,
            "before_source_sha256": BASE_DETECTOR_SHA256,
            "before_dependency_source_sha256": baseline_dependency_hashes,
            "after_source_sha256": current_sha,
            "after_dependency_source_sha256": {
                "detector": current_sha,
                "memory_safety_helper": current_helper_sha,
            },
        },
        "source_identity": {"candidate_rows": all_candidate_count, "unique_source_files": len(inputs), "source_hashes_matched": len(inputs)},
        "before": {"candidate_rows_reproduced": reproduced_rows, "by_callee": dict(sorted(before_counts.items()))},
        "after": {"format_candidate_rows": sum(after_counts.values()), "by_callee": dict(sorted(after_counts.items()))},
        "legacy_literal_prefix_boundary": {
            "description": "The 0.3.0 literal check ignored any expression beginning with a quote; 0.4.0 accepts only a complete literal sequence or literal-only conditional arms.",
            "current_candidates_with_quote_prefixed_expression": sum(legacy_prefix_suppressed.values()),
            "by_callee": dict(sorted(legacy_prefix_suppressed.items())),
            "current_candidates_that_0_3_0_prefix_check_would_keep": sum(legacy_filtered_after_counts.values()),
            "by_callee_kept": dict(sorted(legacy_filtered_after_counts.items())),
            "examples": legacy_prefix_examples,
        },
        "after_file_outcomes": dict(sorted(after_outcomes.items())),
        "after_candidate_expression_census": {
            "count": len(after_candidate_inventory),
            "by_expression_shape": dict(sorted(after_shape_counts.items())),
            "by_callee_and_shape": {
                f"{callee}:{shape}": count
                for (callee, shape), count in sorted(after_shape_by_callee.items())
            },
            "items": after_candidate_inventory,
            "interpretation": "Lexical expression-shape inventory for the replayed findings. Categories describe syntax only; they are not vulnerability labels or proof that macros expand to fixed/dynamic formats.",
        },
        "after_signature_unknown_files": after_signature_unknown_files,
        "changes": dict(sorted(change_counts.items())),
        "examples": examples,
        "tooling": {"python": platform.python_version(), "mode": "in-process detector replay; no CFG or product-build claim"},
        "interpretation": "This replay measures API-argument-position correction and the 0.4.0 expression-classification boundary on the exact source files that previously produced fprintf/vfprintf findings. Compared with 0.3.0, expressions that merely begin with a literal prefix but contain trailing tokens are now surfaced; this is a behavior expansion, not an accuracy result. Remaining format expressions still need independent source/control review.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "candidate_rows": all_candidate_count, "files": len(inputs), "before": dict(before_counts), "after": dict(after_counts), "legacy_prefix_suppressed": dict(legacy_prefix_suppressed), "legacy_filtered_after": dict(legacy_filtered_after_counts), "changes": dict(change_counts), "after_file_outcomes": dict(after_outcomes), "signature_unknown_files": len(after_signature_unknown_files), "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
