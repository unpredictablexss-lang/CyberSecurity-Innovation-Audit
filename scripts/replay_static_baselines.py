"""Replay own text/AST baselines from fixed historical Git blobs.

Run from the repository root: python -m scripts.replay_static_baselines
    --target-root /path/to/component-repos --output-dir outputs/reports/closure
Only reads local target repositories; never fetches, builds or checks out code.
"""

import argparse
import json
import platform
import tempfile
import time
from importlib.metadata import version
from pathlib import Path

from src.benchmark.historical import load_sample, run_historical_benchmark, _show_file
from src.benchmark.report_inputs import DEFAULT_TOOLS, load_report_runs
from src.benchmark.tool_matrix import build_tool_matrix, write_reports as write_matrix
from src.benchmark.tool_result import ToolDiagnostic, ToolRunResult
from src.core.ast_scanner import scan_directory_ast
from src.core.scanner import scan_directory
from src.report.benchmark_report import build_benchmark_report, write_reports


def replay_baselines(samples_dir: Path, target_root: Path, output_dir: Path, fallback_roots=()):
    output_dir.mkdir(parents=True, exist_ok=True)
    sample_paths = sorted(samples_dir.glob("*.json"))
    if not sample_paths:
        raise ValueError("no historical sample manifests found")
    samples, entries, failures = [], [], []
    for sample_path in sample_paths:
        sample = load_sample(sample_path)
        # Verifies exact commits and published fix metadata before materialization.
        samples.append(sample)
        attempts = []
        historical = None
        for source_root in (target_root, *fallback_roots):
            repo = source_root / sample.repository.rsplit("/", 1)[-1]
            try:
                historical = run_historical_benchmark(sample_path, repo)
                break
            except (OSError, ValueError, RuntimeError) as error:
                attempts.append({"repo": str(repo), "reason": str(error)})
        if historical is None:
            failures.append({"sample_id": sample.sample_id, "attempts": attempts})
            continue
        (output_dir / f"{sample_path.stem}.historical.json").write_text(
            json.dumps(historical.to_dict(), indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        for revision in ("vulnerable", "fixed"):
            commit = getattr(sample, f"{revision}_commit")
            report_paths = []
            with tempfile.TemporaryDirectory(prefix="oh-static-baseline-") as directory:
                root = Path(directory).resolve()
                for file in sample.affected_files:
                    path = (root / file).resolve()
                    if not path.is_relative_to(root):
                        raise ValueError("affected file escapes snapshot root")
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text(_show_file(repo, commit, file), encoding="utf-8")
                for engine, scan in (("text", scan_directory), ("ast", scan_directory_ast)):
                    started = time.perf_counter()
                    result = scan(root, include_paths=sample.affected_files)
                    elapsed = time.perf_counter() - started
                    parsing = [{**item, "file": Path(item["file"]).relative_to(root).as_posix()}
                               for item in result.parsing]
                    diagnostics = [ToolDiagnostic(
                        diagnostic_id=f"{engine}:{index}", provider=f"own_{engine}",
                        evidence_type="syntax" if engine == "ast" else "pattern",
                        file=Path(finding.file_path).relative_to(root).as_posix(), line=finding.line,
                        column=None, rule_id=finding.rule_id, severity=finding.severity,
                        message=finding.explanation, candidate_cwe=finding.cwe, symbol=finding.function,
                    ) for index, finding in enumerate(result.findings)]
                    normalized = ToolRunResult(
                        schema_version=1, run_id=f"{sample.sample_id}:{revision}:{engine}",
                        tool=f"own_{engine}", tool_version=f"tree-sitter {version('tree-sitter')}" if engine == "ast" else "text-v1",
                        target_id=sample.sample_id, commit=commit, scope_files=result.scanned_files,
                        scope_loc=result.scanned_lines, status="blocked" if result.skipped_files else "completed",
                        elapsed_seconds=elapsed, diagnostics=diagnostics, parsing=parsing,
                        limitations=["Own dangerous-API candidates only; no semantic vulnerability verdict."],
                    )
                    filename = f"{sample_path.stem}.{revision}.{engine}.json"
                    report_path = output_dir / filename
                    report_path.write_text(json.dumps(normalized.to_dict(), indent=2) + "\n", encoding="utf-8")
                    report_paths.append(report_path)
                    entry = {"sample_id": sample.sample_id, "revision": revision, "report": filename,
                             "analyzed_files": sample.affected_files}
                    if result.skipped_files:
                        entry["reason"] = "; ".join(result.skipped_files)
                    entries.append(entry)
            # A blocked tool run stays in the summary; it is not comparable.
            if not any("reason" in entry for entry in entries[-2:]):
                write_matrix(build_tool_matrix(report_paths), output_dir / f"{sample_path.stem}.{revision}.matrix.json",
                             output_dir / f"{sample_path.stem}.{revision}.matrix.md")
    manifest_path = output_dir / "inputs.json"
    manifest_path.write_text(json.dumps({"schema_version": 1, "runs": entries,
                                        "environment": {"python": platform.python_version(), "system": platform.platform()}},
                                       indent=2) + "\n", encoding="utf-8")
    (output_dir / "failures.json").write_text(json.dumps(failures, indent=2) + "\n", encoding="utf-8")
    summary = build_benchmark_report(samples, runs=load_report_runs(manifest_path, samples), tools=DEFAULT_TOOLS)
    write_reports(summary, output_dir / "summary.json", output_dir / "summary.md")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples-dir", type=Path, default=Path("benchmarks/historical"))
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--fallback-target-root", type=Path, action="append", default=[])
    parser.add_argument("--output-dir", type=Path, default=Path("outputs/reports/static_baselines"))
    args = parser.parse_args()
    try:
        summary = replay_baselines(args.samples_dir.resolve(), args.target_root.resolve(), args.output_dir.resolve(),
                                   fallback_roots=[path.resolve() for path in args.fallback_target_root])
    except (OSError, ValueError, RuntimeError) as error:
        parser.error(str(error))
    print(f"[OK] samples: {summary.sample_count}; matrix rows: {len(summary.root_cause_matrix.rows)}")


if __name__ == "__main__":
    main()
