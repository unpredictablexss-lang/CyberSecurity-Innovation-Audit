import argparse
import json
from pathlib import Path

from src.baseline.clang_analyzer import run_clang_analyzer, write_reports as write_clang_reports
from src.benchmark.historical import run_historical_benchmark, write_reports as write_historical_reports
from src.benchmark.compare import compare_normalized_reports, write_reports as write_comparison_reports
from src.benchmark.scanner_compare import compare_text_and_ast, write_reports as write_scanner_compare_reports
from src.core.report import render_markdown
from src.core.ast_scanner import scan_directory_ast
from src.core.scanner import scan_directory
from src.triage.review import build_triage_report, write_triage_reports
from src.validation.cjson_allocator import (
    PINNED_CJSON_COMMIT,
    run_cjson_allocator_validation,
    write_reports as write_allocator_reports,
)


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

    args = parser.parse_args()

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
