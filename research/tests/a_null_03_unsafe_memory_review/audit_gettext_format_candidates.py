from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
WORKSPACE = ROOT.parent
CENSUS_DEFAULT = ROOT / "research/evidence/cpp/a_unsafe_memory_review_20261018/format_argument_positions_before_after_20261019_v8.json"
SCAN_DEFAULT = WORKSPACE / "openharmony-abcd-full-scan-20261018-final"
SOURCE_DEFAULT = WORKSPACE / "openharmony"
OUTPUT_DEFAULT = ROOT / "research/evidence/cpp/a_unsafe_memory_review_20261018/gettext_format_candidate_source_audit_20261019_v3.json"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.detectors.cpp.unsafe_memory_call_detector import _is_literal_format_expression


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit source identity and direct gettext-wrapper context for replayed format candidates")
    parser.add_argument("--census", type=Path, default=CENSUS_DEFAULT)
    parser.add_argument("--scan-root", type=Path, default=SCAN_DEFAULT)
    parser.add_argument("--source-root", type=Path, default=SOURCE_DEFAULT)
    parser.add_argument("--output", type=Path, default=OUTPUT_DEFAULT)
    args = parser.parse_args()

    census_bytes = args.census.read_bytes()
    census = json.loads(census_bytes)
    with (args.scan_root / "project_summary.csv").open(encoding="utf-8-sig", newline="") as source:
        projects = {row["repository"]: row for row in csv.DictReader(source)}

    rows = [
        item for item in census["after_candidate_expression_census"]["items"]
        if item["expression_shape"] == "call_or_macro_invocation"
        and re.match(r"^_\s*\(", item["expression"])
    ]
    counts: Counter[str] = Counter()
    audited = []
    for item in rows:
        project = projects[item["repository"]]
        path = args.source_root / project["project_path"] / item["file"]
        source_bytes = path.read_bytes()
        if sha256(source_bytes) != item["source_sha256"]:
            raise ValueError(f"source hash mismatch: {item['repository']}:{item['file']}")
        text = source_bytes.decode("utf-8", errors="replace")
        expression = item["expression"].strip()
        open_paren = expression.find("(")
        close_paren = expression.rfind(")")
        if open_paren < 0 or close_paren <= open_paren:
            raise ValueError(f"unexpected wrapper expression: {item['expression']}")
        argument = expression[open_paren + 1:close_paren].strip()
        literal_argument = _is_literal_format_expression(argument)
        local_underscore_define = bool(
            re.search(r"^\s*#\s*define\s+_\s*(?:\([^\n]*\))?", text, re.MULTILINE)
        )
        direct_gettext_header = bool(
            re.search(r"^\s*#\s*include\s*[<\"](?:libintl\.h|gettext\.h)[>\"]", text, re.MULTILINE)
        )
        counts["source_hash_matched"] += 1
        counts["literal_wrapper_argument" if literal_argument else "nonliteral_wrapper_argument"] += 1
        counts["same_file_underscore_define" if local_underscore_define else "no_same_file_underscore_define"] += 1
        counts["direct_gettext_header" if direct_gettext_header else "no_direct_gettext_header"] += 1
        audited.append({
            "repository": item["repository"],
            "file": item["file"],
            "source_sha256": item["source_sha256"],
            "line": item["line"],
            "expression": expression,
            "wrapper_argument_is_literal_sequence": literal_argument,
            "same_file_underscore_define": local_underscore_define,
            "direct_gettext_header": direct_gettext_header,
        })

    artifact = {
        "schema_version": "ohscanner.a-unsafe-gettext-format-source-audit-v1",
        "census_sha256": sha256(census_bytes),
        "source_run_signature": census["source_run_signature"],
        "candidate_subset": "0.4.0 fprintf/vfprintf observations from the pinned 829-file replay whose expression shape is an outer _() wrapper",
        "counts": {"rows": len(rows), **dict(sorted(counts.items()))},
        "interpretation": "This audit verifies source identity, literal syntax inside the wrapper, and only same-file definitions/direct gettext includes. It does not resolve transitive headers, catalog contents, active preprocessor branches, runtime control, or vulnerability truth.",
        "items": audited,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(artifact, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "counts": artifact["counts"], "output": str(args.output)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
