import argparse
import json
from pathlib import Path

from src.core.report import render_markdown
from src.core.scanner import scan_directory


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberSecurity Innovation Audit MVP candidate scanner"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a source directory")
    scan_parser.add_argument("target", help="Target source directory")
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

    args = parser.parse_args()

    if args.command == "scan":
        target = Path(args.target).resolve()
        json_output = Path(args.json_out).resolve()
        md_output = Path(args.md_out).resolve()

        if not target.is_dir():
            scan_parser.error(f"target is not a directory: {target}")
        if json_output == md_output:
            scan_parser.error("JSON and Markdown output paths must differ")

        result = scan_directory(target)
        json_output.parent.mkdir(parents=True, exist_ok=True)
        md_output.parent.mkdir(parents=True, exist_ok=True)
        json_output.write_text(
            json.dumps(result.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        md_output.write_text(render_markdown(result), encoding="utf-8")

        print(f"[OK] scanned: {result.target}")
        print(f"[OK] scanned files: {result.scanned_files}")
        print(f"[OK] scanned lines: {result.scanned_lines}")
        print(f"[OK] skipped source files: {len(result.skipped_files)}")
        print(f"[OK] candidate findings: {result.finding_count}")
        print(f"[OK] json report: {json_output}")
        print(f"[OK] markdown report: {md_output}")


if __name__ == "__main__":
    main()
