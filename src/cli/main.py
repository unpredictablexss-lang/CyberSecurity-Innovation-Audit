import argparse
import json
from pathlib import Path

from src.core.scanner import scan_directory


def main() -> None:
    parser = argparse.ArgumentParser(
        description="CyberSecurity Innovation Audit MVP scanner"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a source directory")
    scan_parser.add_argument("target", help="Target source directory")
    scan_parser.add_argument("--out", default="outputs/reports/report.json", help="Output JSON path")

    args = parser.parse_args()

    if args.command == "scan":
        target = Path(args.target).resolve()
        output = Path(args.out).resolve()

        findings = scan_directory(target)
        output.parent.mkdir(parents=True, exist_ok=True)

        data = {
            "target": str(target),
            "finding_count": len(findings),
            "findings": [item.to_dict() for item in findings],
        }

        output.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

        print(f"[OK] scanned: {target}")
        print(f"[OK] findings: {len(findings)}")
        print(f"[OK] report: {output}")


if __name__ == "__main__":
    main()
