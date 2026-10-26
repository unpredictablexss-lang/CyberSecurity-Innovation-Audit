from __future__ import annotations

import argparse
import csv
import hashlib
import importlib.util
import json
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKSPACE = ROOT.parent
RULE_ID = "ohcpp-format-string-candidate-002"
DETECTOR_ID = "ohscanner.cpp.unsafe_memory_call"
DETECTOR_PATH = "src/ohscanner/detectors/cpp/unsafe_memory_call_detector.py"
REPORT_PATH = ROOT / "research/evidence/cpp/a_unsafe_memory_review_20261018/literal_format_conditional_replay_20261019.json"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.cpp.unsafe_memory_call_detector import CppUnsafeMemoryCallDetector


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def source_path(scan_root: Path, repo: str, relative_path: str, projects: dict[str, dict]) -> Path:
    project = projects[repo]
    source_root = WORKSPACE / "openharmony"
    return source_root / project["project_path"] / Path(relative_path)


def load_scan_detector(commit: str):
    raw = subprocess.run(
        ["git", "show", f"{commit}:{DETECTOR_PATH}"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        timeout=10,
    ).stdout
    name = "src.ohscanner.detectors.cpp.unsafe_memory_call_detector_audit_scan"
    spec = importlib.util.spec_from_loader(name, loader=None)
    if spec is None:
        raise RuntimeError("could not initialize pinned scan detector")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    exec(compile(raw.decode("utf-8"), f"{commit}:{DETECTOR_PATH}", "exec"), module.__dict__)
    return module.CppUnsafeMemoryCallDetector


def run(detector_type, repository: str, commit: str, relative_path: str, data: bytes):
    source = data.decode("utf-8")
    unit = SourceUnit(relative_path, "cpp", source, digest(data), "complete")
    request = ScanRequest(
        request_id="audit-format:" + digest(data)[:16],
        repository=repository,
        commit=commit,
        snapshot_sha256=snapshot_digest((unit,)),
        target_id="current-component:" + repository,
        profile_id="light-ast",
        provenance="git_object",
    )
    result = detector_type().detect(ScanContext(request, (unit,), {}), (unit,))
    sites = {
        (finding.line, finding.column)
        for finding in result.findings
        if finding.rule_id == RULE_ID
    }
    return sites


def main() -> int:
    parser = argparse.ArgumentParser(description="Second-harness audit of the conditional format replay")
    parser.add_argument("--scan-root", type=Path, default=WORKSPACE / "openharmony-abcd-full-scan-20261018-final")
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    results_csv = args.scan_root / "candidate_results.csv"
    config = json.loads((args.scan_root / "run_config.json").read_text(encoding="utf-8"))
    if digest(results_csv.read_bytes()) != report["candidate_results_sha256"]:
        raise ValueError("candidate CSV hash differs from replay report")
    if config["run_signature"] != report["source_run_signature"]:
        raise ValueError("source run signature differs from replay report")
    if config["scanner_commit"] != report["scanner_commit"]:
        raise ValueError("scanner commit differs from replay report")

    projects: dict[str, dict] = {}
    with (args.scan_root / "project_summary.csv").open(encoding="utf-8-sig", newline="") as source:
        projects.update({row["repository"]: row for row in csv.DictReader(source)})
    result_rows: dict[tuple[str, str], list[dict]] = defaultdict(list)
    with results_csv.open(encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            if row.get("rule_id") == RULE_ID and "?" in row.get("symbol", ""):
                result_rows[(row["repository"], row["file"])].append(row)

    report_rows = {
        (item["repository"], item["file"], item["line"], item["diagnostic_id"]): item
        for item in report["rows"]
    }
    if len(report_rows) != 14 or sum(map(len, result_rows.values())) != 14:
        raise ValueError("expected 14 unique conditional-format observations")
    before_type = load_scan_detector(config["scanner_commit"])
    if before_type.version != report["before_detector"]["version"]:
        raise ValueError("pinned detector version differs from report")
    before_source = subprocess.run(
        ["git", "show", f"{config['scanner_commit']}:{DETECTOR_PATH}"], cwd=ROOT,
        check=True, capture_output=True, timeout=10,
    ).stdout
    if digest(before_source.replace(b"\r\n", b"\n")) != report["before_detector"]["source_sha256"]:
        raise ValueError("pinned detector hash differs from report")

    current_source = (ROOT / DETECTOR_PATH).read_bytes()
    current_hash = digest(current_source)
    if current_hash != report["after_detector"]["source_sha256"]:
        raise ValueError("current detector source hash differs from report")
    if CppUnsafeMemoryCallDetector.version != report["after_detector"]["version"]:
        raise ValueError("current detector version differs from report")

    outcomes = Counter()
    checked_rows = 0
    for (repository, relative_path), rows in sorted(result_rows.items()):
        project = projects[repository]
        result_path = Path(rows[0]["result_path"].replace("/mnt/d/openHarmonyScanner/", "D:/openHarmonyScanner/"))
        scan_result = json.loads(result_path.read_text(encoding="utf-8"))
        detector_run = next(item for item in scan_result["detector_runs"] if item["tool"] == DETECTOR_ID)
        diagnostics = {item["diagnostic_id"]: item for item in detector_run["diagnostics"]}
        data = source_path(args.scan_root, repository, relative_path, projects).read_bytes()
        source_hash = digest(data)
        if len({diagnostics[row["diagnostic_id"]].get("source_sha256") for row in rows}) != 1:
            raise ValueError(f"inconsistent diagnostic source hashes for {repository}:{relative_path}")
        if diagnostics[rows[0]["diagnostic_id"]].get("source_sha256") != source_hash:
            raise ValueError(f"source hash mismatch for {repository}:{relative_path}")
        before_sites = run(before_type, repository, project["manifest_commit"], relative_path, data)
        after_sites = run(CppUnsafeMemoryCallDetector, repository, project["manifest_commit"], relative_path, data)
        for row in rows:
            original = diagnostics[row["diagnostic_id"]]
            if original.get("message") != row["message"] or int(original["line"]) != int(row["line"]):
                raise ValueError(f"CSV/result mismatch at {row['diagnostic_id']}")
            column = int(original["column"])
            line = int(row["line"])
            key = (repository, relative_path, line, row["diagnostic_id"])
            output = report_rows.get(key)
            if output is None or output["source_sha256"] != source_hash:
                raise ValueError(f"replay report row missing or unbound: {row['diagnostic_id']}")
            if (line, column) not in before_sites or not output["before_present"]:
                raise ValueError(f"pinned scan detector no longer reproduces {row['diagnostic_id']}")
            after_present = (line, column) in after_sites
            if after_present != output["after_present"]:
                raise ValueError(f"current detector differs from report at {row['diagnostic_id']}")
            outcomes[(output["classification"], "retained" if after_present else "suppressed")] += 1
            checked_rows += 1

    expected = Counter({("literal_arms", "suppressed"): 8, ("nonliteral_or_macro_arms", "retained"): 6})
    if outcomes != expected or checked_rows != 14:
        raise ValueError(f"unexpected audited behavior: {dict(outcomes)}")
    audit = {
        "schema_version": "ohscanner.a-unsafe-literal-format-replay-audit-v1",
        "status": "passed",
        "verifier_sha256": digest(Path(__file__).read_bytes()),
        "replay_report_sha256": digest(args.report.read_bytes()),
        "candidate_results_sha256": digest(results_csv.read_bytes()),
        "method": "second local replay harness against raw candidate CSV, result JSON, pinned scan detector, exact source hashes, and current detector",
        "external_independent_reviewer": "not_performed",
        "counts": {
            "raw_candidate_rows": sum(map(len, result_rows.values())),
            "report_rows_matched": checked_rows,
            "unique_source_files": len(result_rows),
            "source_hashes_matched": len(result_rows),
            "baseline_reproduced": outcomes[("literal_arms", "suppressed")] + outcomes[("nonliteral_or_macro_arms", "retained")],
            "literal_arms_suppressed": outcomes[("literal_arms", "suppressed")],
            "macro_or_dynamic_arms_retained": outcomes[("nonliteral_or_macro_arms", "retained")],
        },
        "source_run_signature": config["run_signature"],
        "pinned_scan_detector": {
            "version": before_type.version,
            "source_sha256": digest(before_source.replace(b"\r\n", b"\n")),
        },
        "current_detector": {"version": CppUnsafeMemoryCallDetector.version, "source_sha256": current_hash},
        "scope_limit": "This verifies replay identity and reported dispositions only; it does not assign vulnerability/safety labels or measure overall accuracy.",
    }
    output = args.report.with_name("literal_format_conditional_replay_audit_20261019.json")
    output.write_text(json.dumps(audit, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": audit["status"], **audit["counts"], "external_independent_reviewer": audit["external_independent_reviewer"], "output": str(output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
