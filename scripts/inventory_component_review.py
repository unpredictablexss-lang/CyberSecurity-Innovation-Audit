"""Generate a candidate context ledger and AST partial-attribution report."""

import argparse
import json
from pathlib import Path

from src.benchmark.component_review import build_review_ledger, render_review_markdown


def inventory(snapshot, reports, output, markdown=None, expected_report_sha256=None):
    ledger = build_review_ledger(snapshot, reports, expected_report_sha256)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(ledger, indent=2))
    if markdown is not None:
        markdown.parent.mkdir(parents=True, exist_ok=True)
        markdown.write_text(render_review_markdown(ledger))
    print("Production review entries:", ledger["counts"]["review_entries"],
          "partial records:", ledger["counts"]["partial_parsing"], flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--reports", type=Path, nargs="+", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--markdown", type=Path)
    parser.add_argument("--expected-report-sha256", action="append", default=[],
                        metavar="REPORT=SHA256")
    args = parser.parse_args()
    expected = {}
    for binding in args.expected_report_sha256:
        if "=" not in binding:
            parser.error("--expected-report-sha256 must use REPORT=SHA256")
        path, digest = binding.split("=", 1)
        expected[str(Path(path).resolve())] = digest
    inventory(args.snapshot.resolve(), [path.resolve() for path in args.reports],
              args.output.resolve(), args.markdown.resolve() if args.markdown else None, expected)
