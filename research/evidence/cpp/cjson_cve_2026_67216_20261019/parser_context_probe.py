"""Research-only, source-bound probe for the local cJSON parser gap.

This does not change scanner input or coverage status. It makes only the two
header-defined macro expansions observed in the pinned component source and
records hashes plus original line locations for review.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from src.parser.ast import parse_source


EXPECTED_CJSON_SHA256 = "427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb"
EXPECTED_HEADER_SHA256 = "25b0145150d500498e4d209cec69c18c42cf818bffcc54690be3b895a2a16dee"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--source", required=True, type=Path)
    ap.add_argument("--header", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()

    source_bytes = args.source.read_bytes()
    header_bytes = args.header.read_bytes()
    source = source_bytes.decode("utf-8")
    header = header_bytes.decode("utf-8")
    source_hash = sha256(source_bytes)
    header_hash = sha256(header_bytes)
    if source_hash != EXPECTED_CJSON_SHA256 or header_hash != EXPECTED_HEADER_SHA256:
        raise SystemExit("source/header identity mismatch; refusing the transformation")

    # cJSON.h defines CJSON_CDECL as empty in its non-Windows branch. This
    # probe explicitly tests that branch; it does not infer product flags.
    cdecl_lines = [i for i, line in enumerate(source.splitlines(), 1) if "CJSON_CDECL" in line]
    normalized = source.replace("CJSON_CDECL", "")

    macro_match = re.search(
        r"^#define\s+cJSON_ArrayForEach\(element,\s*array\)\s+(.+)$",
        header,
        re.MULTILINE,
    )
    if not macro_match:
        raise SystemExit("cJSON_ArrayForEach definition not found in bound header")
    macro_body = macro_match.group(1).strip()
    invocations = list(re.finditer(r"cJSON_ArrayForEach\((\w+),\s*(\w+)\)", normalized))

    def expand(match: re.Match[str]) -> str:
        element, array = match.group(1), match.group(2)
        return macro_body.replace("element", element).replace("array", array)

    normalized = re.sub(r"cJSON_ArrayForEach\((\w+),\s*(\w+)\)", expand, normalized)
    transformed_bytes = normalized.encode("utf-8")
    raw_ast = parse_source(source, "c")
    transformed_ast = parse_source(normalized, "c")
    compare = [f for f in transformed_ast.functions if f.name == "cJSON_Compare"]
    recursive_calls = [
        c.line for c in transformed_ast.calls
        if c.name == "cJSON_Compare" and compare and compare[0].start_line <= c.line <= compare[0].end_line
    ]
    report = {
        "experiment": "research_only_header_macro_expansion_for_parser_diagnostics",
        "source": str(args.source),
        "source_sha256": source_hash,
        "header": str(args.header),
        "header_sha256": header_hash,
        "profile_assumption": "explicit non-Windows CJSON_CDECL empty branch; no product build profile inferred",
        "transformations": [
            {"macro": "CJSON_CDECL", "expansion": "", "source_lines": cdecl_lines},
            {
                "macro": "cJSON_ArrayForEach",
                "expansion_from_bound_header": macro_body,
                "uses": [
                    {"line": source.count("\n", 0, m.start()) + 1, "element": m.group(1), "array": m.group(2)}
                    for m in invocations
                ],
            },
        ],
        "transformed_sha256": sha256(transformed_bytes),
        "line_count_preserved": source.count("\n") == normalized.count("\n"),
        "raw_parse": {"status": raw_ast.parse_status, "issues": raw_ast.parse_issues},
        "transformed_parse": {"status": transformed_ast.parse_status, "issues": transformed_ast.parse_issues},
        "cJSON_Compare_function_ranges": [
            {"start_line": f.start_line, "end_line": f.end_line} for f in compare
        ],
        "recursive_cJSON_Compare_call_lines": recursive_calls,
        "coverage_effect": "none; production scan remains partial until an admitted shared parser context is implemented",
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
