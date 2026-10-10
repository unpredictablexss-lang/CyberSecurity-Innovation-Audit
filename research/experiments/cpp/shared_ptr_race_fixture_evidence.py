"""Run the shared_ptr_race detector over the full synthetic fixture group.

The output is normalized ToolRunResult v1 evidence, written to Git-ignored
paths. This script does not modify public schemas and does not upgrade any
candidate to a vulnerability.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.ohscanner.detectors.cpp.shared_ptr_race_detector import (
    SharedPtrRaceDetector,
)
from src.ohscanner.runner import DetectorRegistry, run_all
from tests.detectors.shared_ptr_race_fixture_support import shared_ptr_race_context


def build() -> str:
    context = shared_ptr_race_context()
    registry = DetectorRegistry()
    registry.register(SharedPtrRaceDetector())
    results = run_all(context, registry)
    normalized_results = []
    for item in results:
        record = item.to_dict()
        record["elapsed_seconds"] = 0.0
        normalized_results.append(record)
    payload = {
        "schema_version": 1,
        "context_request_id": context.request.request_id,
        "results": normalized_results,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def build_markdown(payload_text: str) -> str:
    payload = json.loads(payload_text)
    lines = [
        "# SharedPtrRace fixture evidence",
        "",
        "> Normalized ToolRunResult evidence; not a vulnerability verdict.",
        "",
    ]
    for result in payload["results"]:
        lines.extend(
            [
                f"## {result['tool']} {result['tool_version']}",
                "",
                f"- Status: `{result['status']}`",
                f"- Scope files: **{result['scope_files']}**",
                f"- Diagnostic count: **{result['diagnostic_count']}**",
                "",
            ]
        )
    return "\n".join(lines) + "\n"


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", required=True, type=Path)
    parser.add_argument("--md-out", type=Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="compare existing output with deterministic reconstruction",
    )
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    expected = build()
    expected_md = build_markdown(expected)
    if args.check:
        if not args.json_out.exists() or args.json_out.read_text(encoding="utf-8") != expected:
            raise SystemExit("shared_ptr_race fixture evidence mismatch")
        if args.md_out is not None and (
            not args.md_out.exists()
            or args.md_out.read_text(encoding="utf-8") != expected_md
        ):
            raise SystemExit("shared_ptr_race fixture evidence Markdown mismatch")
        print("[OK] shared_ptr_race fixture evidence matches")
        return 0
    args.json_out.parent.mkdir(parents=True, exist_ok=True)
    args.json_out.write_text(expected, encoding="utf-8")
    if args.md_out is not None:
        args.md_out.parent.mkdir(parents=True, exist_ok=True)
        args.md_out.write_text(expected_md, encoding="utf-8")
    print(f"[OK] wrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
