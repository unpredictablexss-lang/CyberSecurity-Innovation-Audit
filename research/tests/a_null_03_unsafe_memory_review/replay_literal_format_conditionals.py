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
DETECTOR_PATH = "src/ohscanner/detectors/cpp/unsafe_memory_call_detector.py"
HELPER_PATH = "src/ohscanner/detectors/cpp/memory_safety.py"
FORMAT_RULE = "ohcpp-format-string-candidate-002"
CALLEE_NAME_RE = re.compile(r"Candidate only: `([^`]+)`")
RAW_STRING_PREFIX_RE = re.compile(r"^(?:u8|u|U|L)?R\"")

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.cpp.unsafe_memory_call_detector import (
    CppUnsafeMemoryCallDetector,
    _is_literal_format_expression,
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_detector_at(commit: str):
    def source_at(path: str) -> bytes:
        return subprocess.run(
            ["git", "show", f"{commit}:{path}"],
            cwd=ROOT,
            capture_output=True,
            check=True,
            timeout=10,
        ).stdout

    detector_source = source_at(DETECTOR_PATH)
    helper_source = source_at(HELPER_PATH)
    package_name = "src.ohscanner.detectors.cpp_scan_pinned_" + commit[:12]
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
            raise RuntimeError(f"could not create pinned scan module: {name}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        exec(compile(source.decode("utf-8"), f"{commit}:{path}", "exec"), module.__dict__)
    detector = sys.modules[f"{package_name}.unsafe_memory_call_detector"].CppUnsafeMemoryCallDetector
    return detector, {
        "detector": sha256(detector_source.replace(b"\r\n", b"\n")),
        "memory_safety_helper": sha256(helper_source.replace(b"\r\n", b"\n")),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay pinned conditional format candidates")
    parser.add_argument("--scan-root", type=Path, default=WORKSPACE / "openharmony-abcd-full-scan-20261018-final")
    parser.add_argument("--source-root", type=Path, default=WORKSPACE / "openharmony")
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / "research/evidence/cpp/a_unsafe_memory_review_20261018/literal_format_conditional_replay_20261019.json",
    )
    args = parser.parse_args()

    results_path = args.scan_root / "candidate_results.csv"
    project_path = args.scan_root / "project_summary.csv"
    config = json.loads((args.scan_root / "run_config.json").read_text(encoding="utf-8"))
    candidates: dict[tuple[str, str], list[dict]] = defaultdict(list)
    format_expression_census: list[dict] = []
    with results_path.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            if row.get("rule_id") != FORMAT_RULE:
                continue
            callee_match = CALLEE_NAME_RE.search(row.get("message", ""))
            if callee_match and callee_match.group(1) in {"printf", "vprintf", "syslog"}:
                format_expression_census.append(row)
            symbol = row.get("symbol", "")
            direct_raw_literal = (
                "?" not in symbol
                and RAW_STRING_PREFIX_RE.match(symbol.strip()) is not None
                and _is_literal_format_expression(symbol)
            )
            if callee_match and callee_match.group(1) in {"printf", "vprintf"} and ("?" in symbol or direct_raw_literal):
                candidates[(row["repository"], row["file"])].append(row)

    projects = {}
    with project_path.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            projects[row["repository"]] = row
    before_detector, before_dependency_hashes = load_detector_at(config["scanner_commit"])
    if before_detector.version != "0.1.0":
        raise ValueError(f"expected original scan detector 0.1.0, got {before_detector.version}")

    classification = Counter()
    rows_out = []
    source_count = 0
    for (repository, relative_path), rows in sorted(candidates.items()):
        project = projects[repository]
        result_path = Path(rows[0]["result_path"].replace("/mnt/d/openHarmonyScanner/", "D:/openHarmonyScanner/"))
        result = json.loads(result_path.read_text(encoding="utf-8"))
        scan = next(item for item in result["detector_runs"] if item["tool"] == "ohscanner.cpp.unsafe_memory_call")
        diagnostics = {item["diagnostic_id"]: item for item in scan["diagnostics"]}
        for row in rows:
            diagnostic = diagnostics[row["diagnostic_id"]]
            if diagnostic.get("message") != row["message"] or int(diagnostic["line"]) != int(row["line"]):
                raise ValueError(f"CSV/result diagnostic mismatch: {row['diagnostic_id']}")
            if not diagnostic.get("source_sha256"):
                raise ValueError(f"missing source hash: {row['diagnostic_id']}")

        data = (args.source_root / project["project_path"] / Path(relative_path)).read_bytes()
        source_sha = sha256(data)
        if any(diagnostics[row["diagnostic_id"]].get("source_sha256") != source_sha for row in rows):
            raise ValueError(f"source hash mismatch: {repository}:{relative_path}")
        unit = SourceUnit(relative_path, "cpp", data.decode("utf-8"), source_sha, "complete")
        request = ScanRequest(
            request_id="literal-format:" + source_sha[:16],
            repository=repository,
            commit=project["manifest_commit"],
            snapshot_sha256=snapshot_digest((unit,)),
            target_id="current-component:" + repository,
            profile_id="light-ast",
            provenance="git_object",
        )
        context = ScanContext(request, (unit,), {})
        before = before_detector().detect(context, (unit,))
        after = CppUnsafeMemoryCallDetector().detect(context, (unit,))
        source_count += 1
        before_sites = {(item.line, item.column): item for item in before.findings if item.rule_id == FORMAT_RULE}
        after_sites = {(item.line, item.column): item for item in after.findings if item.rule_id == FORMAT_RULE}
        for row in rows:
            diagnostic = diagnostics[row["diagnostic_id"]]
            key = (int(row["line"]), int(diagnostic["column"]))
            if key not in before_sites:
                raise ValueError(f"pinned scan detector did not reproduce candidate at {repository}:{relative_path}:{key[0]}")
            expression = row.get("symbol", "")
            literal = _is_literal_format_expression(expression)
            direct_raw_literal = "?" not in expression and RAW_STRING_PREFIX_RE.match(expression.strip()) is not None
            disposition = (
                "direct_raw_string" if direct_raw_literal
                else "literal_arms" if literal
                else "nonliteral_or_macro_arms"
            )
            classification[disposition] += 1
            retained = key in after_sites
            if retained == literal:
                raise ValueError(f"unexpected 0.5.0 disposition at {repository}:{relative_path}:{key[0]}")
            rows_out.append({
                "repository": repository,
                "file": relative_path,
                "line": key[0],
                "column": key[1],
                "source_sha256": source_sha,
                "diagnostic_id": row["diagnostic_id"],
                "classification": disposition,
                "before_present": True,
                "after_present": retained,
            })

    expected = {"literal_arms": 8, "nonliteral_or_macro_arms": 6, "direct_raw_string": 4}
    if len(rows_out) != 18 or dict(classification) != expected:
        raise ValueError(f"unexpected candidate distribution: {dict(classification)}")
    census_by_callee = Counter()
    literal_census_ids = set()
    conditional_census_rows = 0
    for row in format_expression_census:
        match = CALLEE_NAME_RE.search(row.get("message", ""))
        callee = match.group(1) if match else "unknown"
        census_by_callee[callee] += 1
        if "?" in row.get("symbol", ""):
            conditional_census_rows += 1
        if _is_literal_format_expression(row.get("symbol", "")):
            literal_census_ids.add(row["diagnostic_id"])
    replayed_literal_ids = {
        item["diagnostic_id"] for item in rows_out
        if item["classification"] in {"literal_arms", "direct_raw_string"}
    }
    if len(format_expression_census) != 157 or dict(census_by_callee) != {"printf": 129, "syslog": 5, "vprintf": 23}:
        raise ValueError(f"unexpected CSV-recorded standard format expression census: {dict(census_by_callee)}")
    if conditional_census_rows != 14 or literal_census_ids != replayed_literal_ids or len(literal_census_ids) != 12:
        raise ValueError(
            "literal expression census does not reconcile to the hash-bound conditional replay: "
            f"conditional={conditional_census_rows}, literals={len(literal_census_ids)}, "
            f"unreplayed={sorted(literal_census_ids - replayed_literal_ids)}, "
            f"unexpected_replay={sorted(replayed_literal_ids - literal_census_ids)}"
        )
    artifact = {
        "schema_version": "ohscanner.a-unsafe-literal-format-conditional-replay-v1",
        "source_run_signature": config["run_signature"],
        "scanner_commit": config["scanner_commit"],
        "candidate_results_sha256": sha256(results_path.read_bytes()),
        "before_detector": {"version": before_detector.version, "dependency_source_sha256": before_dependency_hashes},
        "after_detector": {
            "version": CppUnsafeMemoryCallDetector.version,
            "dependency_source_sha256": {
                "detector": sha256((ROOT / DETECTOR_PATH).read_bytes().replace(b"\r\n", b"\n")),
                "memory_safety_helper": sha256((ROOT / HELPER_PATH).read_bytes().replace(b"\r\n", b"\n")),
            },
        },
        "scope": "All scan observations for format-rule candidates whose recorded expression contains a conditional operator; exact original source hashes are required.",
        "counts": {
            "candidate_rows": len(rows_out),
            "unique_source_files": source_count,
            "source_hashes_matched": source_count,
            "baseline_reproduced": sum(item["before_present"] for item in rows_out),
            "literal_conditionals_suppressed": sum(item["classification"] == "literal_arms" and not item["after_present"] for item in rows_out),
            "macro_or_dynamic_conditionals_retained": sum(item["classification"] == "nonliteral_or_macro_arms" and item["after_present"] for item in rows_out),
            "direct_raw_literal_candidates_suppressed": sum(item["classification"] == "direct_raw_string" and not item["after_present"] for item in rows_out),
        },
        "csv_recorded_expression_census": {
            "scope": "printf/vprintf/syslog format-rule rows in the pinned candidate CSV; expression census only, not source replay for every row",
            "rows": len(format_expression_census),
            "by_callee": dict(sorted(census_by_callee.items())),
            "conditional_expression_rows": conditional_census_rows,
            "recognized_literal_expression_rows": len(literal_census_ids),
            "additional_literal_expression_outside_replayed_conditionals": sorted(literal_census_ids - replayed_literal_ids),
        },
        "rows": rows_out,
        "tooling": {"python": platform.python_version(), "mode": "in-process pinned source replay; no CFG or accuracy claim"},
        "interpretation": "This replay validates a syntax-based suppression boundary on exact previously observed source locations. It does not establish security safety, exploitability, or a false-positive rate.",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", **artifact["counts"], "classification": dict(classification), "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

