import argparse
import json
import subprocess
import sys
from pathlib import Path

from src.baseline.clang_analyzer import run_clang_analyzer, write_reports as write_clang_reports
from src.benchmark.historical import run_historical_benchmark, write_reports as write_historical_reports
from src.benchmark.compare import compare_normalized_reports, write_reports as write_comparison_reports
from src.benchmark.scanner_compare import compare_text_and_ast, write_reports as write_scanner_compare_reports
from src.core.report import render_markdown
from src.core.ast_scanner import scan_directory_ast
from src.core.scanner import scan_directory
from src.triage.review import build_triage_report, write_triage_reports
from src.benchmark.tool_result import write_reports as write_tool_reports
from src.providers.base import AdapterContext
from src.providers.registry import normalize_tool_output
from src.benchmark.historical import load_sample
from src.benchmark.report_inputs import DEFAULT_TOOLS, load_report_runs
from src.report.benchmark_report import build_benchmark_report, write_reports as write_benchmark_reports
from src.validation.cjson_allocator import (
    PINNED_CJSON_COMMIT,
    run_cjson_allocator_validation,
    write_reports as write_allocator_reports,
)


def _read_tool_payload(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def _configure_scan_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    scan_parser = subparsers.add_parser("scan", help="Scan a source directory")
    scan_parser.add_argument("target", help="Target source directory")
    scan_parser.add_argument(
        "--include",
        action="append",
        default=None,
        metavar="PATH",
        help=(
            "Relative file or directory to include under target. "
            "Repeat to include multiple paths. Default: entire target."
        ),
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=None,
        metavar="PATH",
        help=(
            "Relative file or directory to exclude under target. "
            "Repeat to exclude multiple paths."
        ),
    )
    scan_parser.add_argument(
        "--engine",
        choices=["text", "ast"],
        default="text",
        help="Candidate engine: text (regex) or ast (tree-sitter). Default: text.",
    )
    scan_parser.add_argument(
        "--json-out",
        "--out",
        dest="json_out",
        default="outputs/reports/report.json",
        help="Output JSON path (--out is retained for compatibility)",
    )
    scan_parser.add_argument(
        "--md-out",
        default="outputs/reports/report.md",
        help="Output Markdown path",
    )
    return scan_parser


def _configure_clang_baseline_parser(
    subparsers: argparse._SubParsersAction,
) -> argparse.ArgumentParser:
    baseline_parser = subparsers.add_parser(
        "baseline-clang",
        help="Run a reproducible clang --analyze baseline on explicit source files",
    )
    baseline_parser.add_argument("target", help="Target source directory")
    baseline_parser.add_argument(
        "--file",
        action="append",
        required=True,
        metavar="PATH",
        help=(
            "Relative source file under target. Repeat for multiple files. "
            "The baseline deliberately requires explicit files."
        ),
    )
    baseline_parser.add_argument(
        "--clang",
        default="clang",
        help="Clang executable to invoke (default: clang)",
    )
    baseline_parser.add_argument(
        "--clang-arg",
        action="append",
        default=None,
        metavar="ARG",
        help=(
            "Extra compiler/analyzer argument passed after the target include path. "
            "Repeat to pass multiple arguments."
        ),
    )
    baseline_parser.add_argument(
        "--json-out",
        default="outputs/reports/clang_baseline.json",
        help="Output JSON path",
    )
    baseline_parser.add_argument(
        "--md-out",
        default="outputs/reports/clang_baseline.md",
        help="Output Markdown path",
    )
    return baseline_parser


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberSecurity Innovation Audit tooling"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = _configure_scan_parser(subparsers)
    baseline_parser = _configure_clang_baseline_parser(subparsers)

    ohscan_parser = subparsers.add_parser(
        "ohscan", help="M0 self-built mock detector contract smoke test (synthetic fixtures only)"
    )
    ohscan_parser.add_argument("--fixture-root", required=True,
                               help="Directory of synthetic C/C++ and JS/ArkTS test fixtures")
    ohscan_parser.add_argument("--json-out", default="outputs/reports/ohscanner_m0.json")
    ohscan_parser.add_argument("--md-out", default="outputs/reports/ohscanner_m0.md")

    ohscan_index_parser = subparsers.add_parser(
        "ohscan-index", help="M1: index pinned local Git source objects (no vulnerability scan)"
    )
    ohscan_index_parser.add_argument("--repo-dir", required=True,
                                     help="Local checked-out Git repository; source read from commit objects")
    ohscan_index_parser.add_argument("--repository", required=True,
                                     help="Declared repository identity such as openharmony/commonlibrary_c_utils")
    ohscan_index_parser.add_argument("--commit", required=True,
                                     help="Complete immutable Git commit SHA, not HEAD/branch/tag")
    ohscan_index_parser.add_argument("--include", action="append", default=None,
                                     help="Repository-relative source path or directory prefix (repeatable)")
    ohscan_index_parser.add_argument("--json-out", default="outputs/reports/ohscanner_m1_index.json")
    ohscan_index_parser.add_argument("--md-out", default="outputs/reports/ohscanner_m1_index.md")

    m2_parser = subparsers.add_parser(
        "ohscan-run",
        help="M2: run explicitly allowlisted first-party detector(s) on pinned local Git sources",
    )
    m2_parser.add_argument("--repo-dir", required=True, help="Local Git repository with full pinned objects")
    m2_parser.add_argument("--repository", required=True, help="Owner/repository declaration")
    m2_parser.add_argument("--commit", required=True, help="Complete immutable Git commit SHA")
    m2_parser.add_argument("--include", action="append", default=None,
                           help="Repository-relative path or prefix; repeatable")
    m2_parser.add_argument("--detector", action="append", required=False, default=None,
                           help="Explicit first-party detector ID; repeatable. Omit to auto-select approved security detectors. Not an import path.")
    m2_parser.add_argument("--allow-example-detectors", action="store_true",
                           help="Acknowledge that 'ohscanner.example.*' is a non-security demonstration")
    m2_parser.add_argument("--json-out", default="outputs/reports/ohscanner_m2.json")
    m2_parser.add_argument("--md-out", default="outputs/reports/ohscanner_m2.md")

    halfyear_parser = subparsers.add_parser(
        "ohscan-halfyear",
        help="Bounded first-parent half-year changed-source candidate MVP",
    )
    halfyear_parser.add_argument("--repo-dir", required=True,
                                 help="Local Git repository with complete pinned objects")
    halfyear_parser.add_argument("--repository", required=True,
                                 help="Owner/repository declaration such as openharmony/commonlibrary_c_utils")
    halfyear_parser.add_argument("--branch", default="HEAD",
                                 help="Local branch/ref to select; default HEAD")
    halfyear_parser.add_argument("--start", required=True,
                                 help="Inclusive ISO-8601 committer-time window start")
    halfyear_parser.add_argument("--end", required=True,
                                 help="Exclusive ISO-8601 committer-time window end")
    halfyear_parser.add_argument("--timezone", default="Asia/Shanghai",
                                 help="Timezone for naive timestamps; default Asia/Shanghai")
    halfyear_parser.add_argument("--detector", action="append", required=True,
                                 help="Explicit approved detector ID; repeatable")
    halfyear_parser.add_argument("--max-commits", type=int, default=5000,
                                 help="Maximum first-parent commits to inspect; default 5000")
    halfyear_parser.add_argument("--shard-size", type=int, default=32,
                                 help="Deterministic commit shard size; coverage is aggregated unchanged")
    halfyear_parser.add_argument("--cache-dir",
                                 help="Optional incremental scan cache outside the output directory")
    halfyear_parser.add_argument("--max-wall-seconds", type=float,
                                 help="Optional wall-time budget; exhausted commits remain unknown")
    halfyear_parser.add_argument("--max-source-files", type=int, default=2000)
    halfyear_parser.add_argument("--max-source-bytes", type=int, default=32 * 1024 * 1024)
    halfyear_parser.add_argument("--max-blob-bytes", type=int, default=1024 * 1024)
    halfyear_parser.add_argument("--max-git-batch-objects", type=int, default=256)
    halfyear_parser.add_argument("--max-output-bytes", type=int, default=256 * 1024 * 1024)
    halfyear_parser.add_argument("--out-dir",
                                 default="outputs/reports/halfyear_candidate_mvp",
                                 help="Output directory for aggregate and per-commit evidence")
    cross_version_parser = subparsers.add_parser(
        "ohscan-cross-version",
        help="Build an evidence-gated cross-version impact package from fixed local objects",
    )
    cross_version_parser.add_argument("--manifest", required=True,
                                      help="Cross-version comparison manifest JSON")
    cross_version_parser.add_argument("--repo-dir", required=True,
                                      help="Local Git repository with complete pinned objects")
    cross_version_parser.add_argument("--out-dir", required=True,
                                      help="Output directory for the evidence package")
    cross_version_parser.add_argument("--component-repo", action="append", default=[],
                                      help="Multi-repo binding COMPONENT_ID=PATH; repeatable")
    cross_version_parser.add_argument("--truth-manifest",
                                      help="Optional independent truth manifest for fail-closed metrics")
    cross_version_parser.add_argument("--prediction-manifest",
                                      help="Optional root-cause prediction/truth records")
    historical_parser = subparsers.add_parser(
        "benchmark-historical",
        help="Replay one published vulnerable/fixed commit pair as historical ground truth",
    )
    historical_parser.add_argument(
        "--sample",
        required=True,
        help="Historical sample JSON manifest",
    )
    historical_parser.add_argument(
        "--repo-dir",
        required=True,
        help="Local Git checkout containing both pinned commits",
    )
    historical_parser.add_argument(
        "--json-out",
        default="outputs/reports/historical_benchmark.json",
        help="Output JSON path",
    )
    historical_parser.add_argument(
        "--md-out",
        default="outputs/reports/historical_benchmark.md",
        help="Output Markdown path",
    )

    compare_parser = subparsers.add_parser(
        "compare-tools",
        help="Compare two or more normalized static-analysis reports on the same fixed scope",
    )
    compare_parser.add_argument(
        "--report",
        action="append",
        required=True,
        metavar="JSON",
        help="Normalized ToolRunResult JSON. Repeat for each tool.",
    )
    compare_parser.add_argument(
        "--json-out",
        default="outputs/reports/tool_comparison.json",
        help="Output comparison JSON path",
    )
    compare_parser.add_argument(
        "--md-out",
        default="outputs/reports/tool_comparison.md",
        help="Output comparison Markdown path",
    )

    compare_scanners_parser = subparsers.add_parser(
        "compare-scanners",
        help="Compare text and AST candidate reports on the same target",
    )
    compare_scanners_parser.add_argument(
        "--text-report",
        required=True,
        metavar="JSON",
        help="Text-engine scan report JSON",
    )
    compare_scanners_parser.add_argument(
        "--ast-report",
        required=True,
        metavar="JSON",
        help="AST-engine scan report JSON",
    )
    compare_scanners_parser.add_argument(
        "--json-out",
        default="outputs/reports/scanner_compare.json",
        help="Output comparison JSON path",
    )
    compare_scanners_parser.add_argument(
        "--md-out",
        default="outputs/reports/scanner_compare.md",
        help="Output comparison Markdown path",
    )

    allocator_parser = subparsers.add_parser(
        "validate-cjson-allocator",
        help="Build and run the controlled cJSON allocator robustness harness",
    )
    allocator_parser.add_argument("target", help="Pinned cJSON source directory")
    allocator_parser.add_argument(
        "--harness",
        default="validation/cjson/allocator_robustness.c",
        help="Harness source path",
    )
    allocator_parser.add_argument(
        "--binary",
        default="outputs/bin/cjson_allocator_robustness",
        help="Output binary path",
    )
    allocator_parser.add_argument(
        "--compiler",
        default="clang",
        help="C compiler executable (default: clang)",
    )
    allocator_parser.add_argument(
        "--expected-commit",
        default=PINNED_CJSON_COMMIT,
        help="Required clean cJSON source commit (default: pinned target commit)",
    )
    allocator_parser.add_argument(
        "--repeat",
        type=int,
        default=3,
        help="Repeat each controlled failure case N times (default: 3)",
    )
    allocator_parser.add_argument(
        "--json-out",
        default="outputs/reports/cjson_allocator_validation.json",
        help="Output JSON path",
    )
    allocator_parser.add_argument(
        "--md-out",
        default="outputs/reports/cjson_allocator_validation.md",
        help="Output Markdown path",
    )

    triage_parser = subparsers.add_parser(
        "triage",
        help="Build structured review packets from a candidate scan JSON report",
    )
    triage_parser.add_argument(
        "--scan-report",
        required=True,
        help="Existing candidate scan JSON report",
    )
    triage_parser.add_argument(
        "--json-out",
        default="outputs/reports/triage_packets.json",
        help="Output triage JSON path",
    )
    triage_parser.add_argument(
        "--md-out",
        default="outputs/reports/triage_packets.md",
        help="Output triage Markdown path",
    )

    normalize_parser = subparsers.add_parser(
        "normalize-tool-output",
        help="Normalize one external tool report into a ToolRunResult",
    )
    normalize_parser.add_argument(
        "--provider",
        required=True,
        choices=["semgrep", "codeql", "clang", "clang_sa", "cppcheck", "joern"],
        help="External tool provider adapter",
    )
    normalize_parser.add_argument("--input", required=True, help="Tool-native report file")
    normalize_parser.add_argument("--target-id", required=True, help="Benchmark target id")
    normalize_parser.add_argument("--commit", required=True, help="Pinned source commit")
    normalize_parser.add_argument("--scope-files", type=int, required=True, help="Scanned file count")
    normalize_parser.add_argument("--scope-loc", type=int, required=True, help="Scanned LOC")
    normalize_parser.add_argument("--elapsed-seconds", type=float, required=True, help="Tool run time")
    normalize_parser.add_argument("--peak-memory-mb", type=float, default=None, help="Tool peak memory")
    normalize_parser.add_argument("--run-id", default=None, help="Override run id")
    normalize_parser.add_argument(
        "--json-out",
        default="outputs/reports/normalized_tool.json",
        help="Output normalized JSON path",
    )
    normalize_parser.add_argument(
        "--md-out",
        default="outputs/reports/normalized_tool.md",
        help="Output normalized Markdown path",
    )

    benchmark_report_parser = subparsers.add_parser(
        "benchmark-report",
        help="Generate the historical benchmark summary report",
    )
    benchmark_report_parser.add_argument(
        "--samples-dir",
        default="benchmarks/historical/",
        help="Directory of historical sample JSON manifests",
    )
    benchmark_report_parser.add_argument(
        "--results",
        help="Manifest binding saved tool reports to sample and vulnerable/fixed revision",
    )
    benchmark_report_parser.add_argument(
        "--json-out",
        default="outputs/reports/historical_benchmark_summary.json",
        help="Output summary JSON path",
    )
    benchmark_report_parser.add_argument(
        "--md-out",
        default="outputs/reports/historical_benchmark_summary.md",
        help="Output summary Markdown path",
    )

    args = parser.parse_args()

    if args.command == "ohscan-run":
        from src.ohscanner.execution import run_fixed_commit_scan

        try:
            report = run_fixed_commit_scan(
                repo_dir=Path(args.repo_dir),
                repository=args.repository,
                commit=args.commit,
                includes=tuple(args.include or ["."]),
                detector_ids=tuple(args.detector or ()),
                json_out=Path(args.json_out),
                md_out=Path(args.md_out),
                allow_examples=args.allow_example_detectors,
            )
        except (ValueError, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
            m2_parser.error(str(error))
        print("[OK] M2 pinned-source candidate evidence run; NOT validated vulnerabilities")
        print(f"[OK] source commit: {report['commit']}")
        print(f"[OK] first-party detectors: {report['detector_count']}")
        print(f"[OK] unverified diagnostics: {report['diagnostic_count']}")
        print(f"[OK] run coverage: {report['status']}")
        print(f"[OK] JSON report: {args.json_out}")
        print(f"[OK] Markdown report: {args.md_out}")
        return

    if args.command == "ohscan-halfyear":
        from src.ohscanner.halfyear import run_halfyear_candidate_mvp

        try:
            report = run_halfyear_candidate_mvp(
                repo_dir=Path(args.repo_dir),
                repository=args.repository,
                branch=args.branch,
                start=args.start,
                end=args.end,
                timezone=args.timezone,
                detector_ids=tuple(args.detector or ()),
                out_dir=Path(args.out_dir),
                max_commits=args.max_commits,
                argv=tuple(sys.argv),
                shard_size=args.shard_size,
                cache_dir=Path(args.cache_dir) if args.cache_dir else None,
                max_wall_seconds=args.max_wall_seconds,
                max_source_files=args.max_source_files,
                max_source_bytes=args.max_source_bytes,
                max_blob_bytes=args.max_blob_bytes,
                max_git_batch_objects=args.max_git_batch_objects,
                max_output_bytes=args.max_output_bytes,
            )
        except (ValueError, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
            halfyear_parser.error(str(error))
        totals = report["totals"]
        print("[OK] half-year changed-source candidate MVP; NOT validated vulnerabilities")
        print(f"[OK] repository: {report['repository']}")
        print(f"[OK] selected commits: {totals['selected_commits']}")
        print(f"[OK] scanned commits: {totals['scanned_commits']}")
        print(f"[OK] blocked commits: {totals['blocked_commits']}")
        print(f"[OK] candidate observations: {totals['candidate_observations']}")
        print(f"[OK] report status: {report['status']}")
        print(f"[OK] JSON report: {Path(args.out_dir) / 'halfyear_candidates.json'}")
        print(f"[OK] Markdown report: {Path(args.out_dir) / 'halfyear_candidates.md'}")
        return
    if args.command == "ohscan-cross-version":
        from src.ohscanner.cross_version import build_package

        try:
            component_repo_dirs = {}
            for row in args.component_repo:
                if "=" not in row:
                    cross_version_parser.error("--component-repo must be COMPONENT_ID=PATH")
                component_id, raw_path = row.split("=", 1)
                component_repo_dirs[component_id] = Path(raw_path)
            report = build_package(
                Path(args.manifest),
                Path(args.repo_dir),
                Path(args.out_dir),
                component_repo_dirs=component_repo_dirs,
                argv=tuple(sys.argv),
                truth_manifest_path=(
                    Path(args.truth_manifest) if args.truth_manifest else None
                ),
                prediction_manifest_path=(
                    Path(args.prediction_manifest) if args.prediction_manifest else None
                ),
            )
        except (ValueError, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
            cross_version_parser.error(str(error))
        print("[OK] cross-version impact evidence package; NOT a confirmed vulnerability")
        print(f"[OK] candidates: {len(report['candidates'])}")
        print(f"[OK] JSON report: {Path(args.out_dir) / 'impact_evidence.json'}")
        print(f"[OK] accuracy gate: {report['accuracy_evaluation']['status']}")
        return
    if args.command == "ohscan-index":
        from src.ohscanner.indexing import run_git_index

        try:
            report = run_git_index(
                repo_dir=Path(args.repo_dir),
                repository=args.repository,
                commit=args.commit,
                includes=tuple(args.include or ["."]),
                json_out=Path(args.json_out),
                md_out=Path(args.md_out),
            )
        except (ValueError, OSError, UnicodeError, subprocess.TimeoutExpired) as error:
            ohscan_index_parser.error(str(error))
        print("[OK] M1 pinned Git source index; no vulnerability detection performed")
        print(f"[OK] commit: {report['commit']}")
        print(f"[OK] scanned source files: {report['scope']['selected_source_files']}")
        print(f"[OK] language coverage: {report['coverage']['languages']}")
        print(f"[OK] parsing coverage: {report['coverage']['parsing_status']}")
        print(f"[OK] json index: {args.json_out}")
        print(f"[OK] markdown index: {args.md_out}")
        return

    if args.command == "ohscan":
        from src.ohscanner.smoke import run_mock_smoke

        try:
            result = run_mock_smoke(Path(args.fixture_root),
                                    Path(args.json_out).resolve(),
                                    Path(args.md_out).resolve())
        except (ValueError, OSError, UnicodeError) as error:
            ohscan_parser.error(str(error))
        print("[OK] M0 synthetic contract smoke; NOT a real vulnerability scan")
        print(f"[OK] normalized first-party detector runs: {len(result['runs'])}")
        print(f"[OK] target provenance: {result['provenance']}")
        print(f"[OK] json report: {args.json_out}")
        print(f"[OK] markdown report: {args.md_out}")
        return

    if args.command == "scan":
        target = Path(args.target).resolve()
        json_output = Path(args.json_out).resolve()
        md_output = Path(args.md_out).resolve()

        if not target.is_dir():
            scan_parser.error(f"target is not a directory: {target}")
        if json_output == md_output:
            scan_parser.error("JSON and Markdown output paths must differ")

        try:
            if args.engine == "text":
                result = scan_directory(
                    target,
                    include_paths=args.include,
                    exclude_paths=args.exclude,
                )
            else:
                result = scan_directory_ast(
                    target,
                    include_paths=args.include,
                    exclude_paths=args.exclude,
                )
        except ValueError as error:
            scan_parser.error(str(error))

        json_output.parent.mkdir(parents=True, exist_ok=True)
        md_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        md_output.write_text(render_markdown(result), encoding="utf-8")

        print(f"[OK] scanned: {result.target}")
        print(f"[OK] engine: {result.engine}")
        print(f"[OK] include scope: {', '.join(result.scope_includes)}")
        print(
            f"[OK] exclude scope: "
            f"{', '.join(result.scope_excludes) if result.scope_excludes else '(none)'}"
        )
        print(f"[OK] scanned files: {result.scanned_files}")
        print(f"[OK] scanned lines: {result.scanned_lines}")
        print(f"[OK] skipped source files: {len(result.skipped_files)}")
        print(f"[OK] candidate findings: {result.finding_count}")
        print(f"[OK] json report: {json_output}")
        print(f"[OK] markdown report: {md_output}")
        return

    if args.command == "baseline-clang":
        target = Path(args.target).resolve()
        json_output = Path(args.json_out).resolve()
        md_output = Path(args.md_out).resolve()

        if json_output == md_output:
            baseline_parser.error("JSON and Markdown output paths must differ")

        try:
            result = run_clang_analyzer(
                target=target,
                files=args.file,
                clang_executable=args.clang,
                extra_args=args.clang_arg,
            )
        except (ValueError, RuntimeError, OSError) as error:
            baseline_parser.error(str(error))

        write_clang_reports(result, json_output, md_output)

        print(f"[OK] baseline target: {result.target}")
        print(f"[OK] clang version: {result.clang_version}")
        print(f"[OK] files: {len(result.files)}")
        print(f"[OK] diagnostics: {result.diagnostic_count}")
        print(f"[OK] failed files: {len(result.failed_files)}")
        print(f"[OK] elapsed seconds: {result.elapsed_seconds:.6f}")
        print(f"[OK] json report: {json_output}")
        print(f"[OK] markdown report: {md_output}")
        return


    if args.command == "benchmark-historical":
        sample_path = Path(args.sample).resolve()
        repo_dir = Path(args.repo_dir).resolve()
        json_output = Path(args.json_out).resolve()
        md_output = Path(args.md_out).resolve()

        if not sample_path.is_file():
            historical_parser.error(f"sample manifest does not exist: {sample_path}")
        if json_output == md_output:
            historical_parser.error("JSON and Markdown output paths must differ")

        try:
            result = run_historical_benchmark(sample_path, repo_dir)
        except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as error:
            historical_parser.error(str(error))

        write_historical_reports(result, json_output, md_output)

        print(f"[OK] historical sample: {result.sample.sample_id}")
        print(f"[OK] vulnerable commit exists: {result.vulnerable_commit_exists}")
        print(f"[OK] fixed commit exists: {result.fixed_commit_exists}")
        print(f"[OK] direct parent match: {result.direct_parent_match}")
        print(
            f"[OK] vulnerable/fixed candidates: "
            f"{result.vulnerable.candidate_count}/{result.fixed.candidate_count}"
        )
        print(
            f"[OK] vulnerable/fixed affected-region overlap: "
            f"{result.text_candidate_overlap_in_vulnerable}/"
            f"{result.text_candidate_overlap_in_fixed}"
        )
        print(f"[OK] json report: {json_output}")
        print(f"[OK] markdown report: {md_output}")
        return

    if args.command == "compare-tools":
        report_paths = [Path(value).resolve() for value in args.report]
        json_output = Path(args.json_out).resolve()
        md_output = Path(args.md_out).resolve()

        if json_output == md_output:
            compare_parser.error("JSON and Markdown output paths must differ")
        for path in report_paths:
            if not path.is_file():
                compare_parser.error(f"normalized tool report does not exist: {path}")

        try:
            result = compare_normalized_reports(report_paths)
        except (ValueError, OSError, json.JSONDecodeError) as error:
            compare_parser.error(str(error))

        write_comparison_reports(result, json_output, md_output)

        print(f"[OK] comparison target: {result.target_id}")
        print(f"[OK] comparison commit: {result.commit}")
        print(f"[OK] tools: {len(result.summaries)}")
        print(f"[OK] scope files/loc: {result.scope_files}/{result.scope_loc}")
        print(f"[OK] pairwise comparisons: {len(result.pairwise_overlaps)}")
        print(f"[OK] json report: {json_output}")
        print(f"[OK] markdown report: {md_output}")
        return

    if args.command == "compare-scanners":
        text_path = Path(args.text_report).resolve()
        ast_path = Path(args.ast_report).resolve()
        json_output = Path(args.json_out).resolve()
        md_output = Path(args.md_out).resolve()

        if json_output == md_output:
            compare_scanners_parser.error("JSON and Markdown output paths must differ")
        for path in (text_path, ast_path):
            if not path.is_file():
                compare_scanners_parser.error(f"scan report does not exist: {path}")

        try:
            result = compare_text_and_ast(text_path, ast_path)
        except (ValueError, OSError, json.JSONDecodeError) as error:
            compare_scanners_parser.error(str(error))

        write_scanner_compare_reports(result, json_output, md_output)

        print(f"[OK] comparison target: {result.target}")
        print(f"[OK] text candidates: {result.text_count}")
        print(f"[OK] ast candidates: {result.ast_count}")
        print(f"[OK] overlap: {result.overlap_count}")
        print(f"[OK] text only: {len(result.text_only)}")
        print(f"[OK] ast only: {len(result.ast_only)}")
        print(f"[OK] json report: {json_output}")
        print(f"[OK] markdown report: {md_output}")
        return

    if args.command == "validate-cjson-allocator":
        target = Path(args.target).resolve()
        harness = Path(args.harness).resolve()
        binary = Path(args.binary).resolve()
        json_output = Path(args.json_out).resolve()
        md_output = Path(args.md_out).resolve()

        if json_output == md_output:
            allocator_parser.error("JSON and Markdown output paths must differ")

        try:
            result = run_cjson_allocator_validation(
                target=target,
                harness=harness,
                binary=binary,
                compiler=args.compiler,
                repeats=args.repeat,
                expected_commit=args.expected_commit,
            )
        except (ValueError, OSError) as error:
            allocator_parser.error(str(error))

        write_allocator_reports(result, json_output, md_output)

        sanitizer_runs = sum(1 for item in result.runs if item.sanitizer_detected)
        print(f"[OK] allocator target: {result.target}")
        print(f"[OK] build outcome: {result.build.outcome}")
        print(f"[OK] runtime cases: {len(result.runs)}")
        print(f"[OK] sanitizer-triggered runs: {sanitizer_runs}")
        print(f"[OK] overall outcome: {result.outcome}")
        print(f"[OK] json report: {json_output}")
        print(f"[OK] markdown report: {md_output}")
        return

    if args.command == "benchmark-report":
        samples_dir = Path(args.samples_dir).resolve()
        json_output = Path(args.json_out).resolve()
        md_output = Path(args.md_out).resolve()

        if not samples_dir.is_dir():
            benchmark_report_parser.error(f"samples dir does not exist: {samples_dir}")
        if json_output == md_output:
            benchmark_report_parser.error("JSON and Markdown output paths must differ")

        sample_paths = sorted(samples_dir.glob("*.json"))
        if not sample_paths:
            benchmark_report_parser.error(f"no historical samples found in {samples_dir}")

        try:
            samples = [load_sample(path) for path in sample_paths]
            runs = load_report_runs(Path(args.results).resolve(), samples) if args.results else []
            report = build_benchmark_report(samples, runs=runs, tools=DEFAULT_TOOLS)
        except (OSError, ValueError, json.JSONDecodeError) as error:
            benchmark_report_parser.error(str(error))

        write_benchmark_reports(report, json_output, md_output)

        print(f"[OK] historical samples: {report.sample_count}")
        print(f"[OK] root-cause groups: {', '.join(report.root_cause_group_distribution)}")
        print(f"[OK] validated vulnerability: {report.validated_vulnerability}")
        print(f"[OK] json report: {json_output}")
        print(f"[OK] markdown report: {md_output}")
        return

    if args.command == "normalize-tool-output":
        input_path = Path(args.input).resolve()
        json_output = Path(args.json_out).resolve()
        md_output = Path(args.md_out).resolve()

        if not input_path.is_file():
            normalize_parser.error(f"tool output does not exist: {input_path}")
        if json_output == md_output:
            normalize_parser.error("JSON and Markdown output paths must differ")

        payload = _read_tool_payload(input_path)
        run_id = args.run_id or f"{args.provider}:{args.target_id}:{args.commit[:8]}"
        context = AdapterContext(
            run_id=run_id,
            target_id=args.target_id,
            commit=args.commit,
            scope_files=args.scope_files,
            scope_loc=args.scope_loc,
            elapsed_seconds=args.elapsed_seconds,
            peak_memory_mb=args.peak_memory_mb,
        )
        try:
            result = normalize_tool_output(args.provider, payload, context)
        except (ValueError, TypeError) as error:
            normalize_parser.error(str(error))

        write_tool_reports(result, json_output, md_output)

        print(f"[OK] normalized tool: {result.tool}")
        print(f"[OK] run id: {result.run_id}")
        print(f"[OK] diagnostics: {result.diagnostic_count}")
        print(f"[OK] json report: {json_output}")
        print(f"[OK] markdown report: {md_output}")
        return

    if args.command == "triage":
        scan_report = Path(args.scan_report).resolve()
        json_output = Path(args.json_out).resolve()
        md_output = Path(args.md_out).resolve()

        if not scan_report.is_file():
            triage_parser.error(f"scan report does not exist: {scan_report}")
        if json_output == md_output:
            triage_parser.error("JSON and Markdown output paths must differ")

        try:
            triage_report = build_triage_report(scan_report)
        except (ValueError, OSError, json.JSONDecodeError, KeyError) as error:
            triage_parser.error(str(error))

        write_triage_reports(triage_report, json_output, md_output)

        parsed_count = sum(
            1
            for packet in triage_report.packets
            if packet.call_parse_status == "parsed_text_call"
        )
        unresolved_count = triage_report.packet_count - parsed_count

        print(f"[OK] source scan report: {triage_report.source_report}")
        print(f"[OK] target: {triage_report.target}")
        print(f"[OK] candidate packets: {triage_report.packet_count}")
        print(f"[OK] parsed call expressions: {parsed_count}")
        print(f"[OK] unresolved call expressions: {unresolved_count}")
        print(f"[OK] json triage report: {json_output}")
        print(f"[OK] markdown triage report: {md_output}")


if __name__ == "__main__":
    main()
