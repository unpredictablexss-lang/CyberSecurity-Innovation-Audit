#!/usr/bin/env python3
"""Diagnose parser-partial state for fixed historical Filter parent/fix blobs."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[3]
SOURCE_DIR = ROOT / "research/experiments/ark-runtime-exact-source-20261018/sources"
OUTPUT = ROOT / "research/deliveries/cpp/C_LINE_HISTORICAL_PARTIAL_DIAGNOSIS_20261019.json"
sys.path.insert(0, str(ROOT))
from research.full_scan_20261018.lanes.c.syntax import parse_functions, parser_environment

PROFILES = {
    "parent": ("type-origin-parent.cpp", "830e85b40240677039719fcbf14f721ad3b19050", "054451b1be4f39254d56a1683cc9d1c1b5e55018", "847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422"),
    "fix": ("type-origin-fix.cpp", "a0e30483ab3e4aead67ecfb5c708489915e447f9", "95f54f2875f401afe3167c62f8c1e7799782be8c", "8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e"),
}
TARGET_SUFFIX = "panda::ecmascript::kungfu::BuiltinsTypedArrayStubBuilder::Filter"


def diagnose(name: str, pin: tuple[str, str, str, str]) -> dict:
    filename, commit, expected_blob, expected_sha = pin
    raw = (SOURCE_DIR / filename).read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
    sha = hashlib.sha256(raw).hexdigest()
    if (blob, sha) != (expected_blob, expected_sha):
        raise ValueError(f"pinned fixture identity mismatch: {name}")
    tree, functions = parse_functions(raw)
    targets = [fn for fn in functions if fn.qualified_name.endswith(TARGET_SUFFIX)]
    if len(targets) != 1:
        raise ValueError(f"expected one exact Filter definition in {name}, found {len(targets)}")
    target = targets[0]
    errors = []
    pending = [tree.root_node]
    while pending:
        node = pending.pop()
        if node.type == "ERROR" or node.is_missing:
            errors.append({
                "node_type": node.type,
                "missing": bool(node.is_missing),
                "source_lines": [node.start_point[0] + 1, node.end_point[0] + 1],
                "source_columns": [node.start_point[1] + 1, node.end_point[1] + 1],
                "within_target_function": target.node.start_byte <= node.start_byte <= target.node.end_byte,
                "nearby_source": raw[max(0, node.start_byte - 100):min(len(raw), node.start_byte + 150)].decode("utf-8", "replace"),
            })
        pending.extend(reversed(node.children))
    if len(errors) != 2 or any(row["within_target_function"] for row in errors):
        raise ValueError(f"unexpected parser error layout for {name}: {errors}")
    return {
        "profile": name,
        "commit": commit,
        "file": filename,
        "bytes": len(raw),
        "git_blob_oid": blob,
        "sha256": sha,
        "translation_unit_parse_status": "partial",
        "translation_unit_has_error": bool(tree.root_node.has_error),
        "function_definitions": len(functions),
        "resolved_target": target.qualified_name,
        "target_source_lines": [target.node.start_point[0] + 1, target.node.end_point[0] + 1],
        "target_function_has_error": bool(target.node.has_error),
        "translation_unit_parser_errors": errors,
        "diagnosis": "Both whole-file partial parser nodes are outside the unique Filter definition and occur at macro-sensitive C++ constructs. Function-local syntax is complete; macro expansion, build configuration, and dependency/type semantics remain unverified.",
    }


def main() -> int:
    result = {
        "schema": "c-line-historical-partial-diagnosis-v1",
        "parser_environment": dict(parser_environment()),
        "profiles": [diagnose(name, pin) for name, pin in PROFILES.items()],
        "interpretation_limit": "This narrows the syntactic cause of file-level partial status. It does not upgrade the historical replay, prove preprocessor/build semantics, or admit the public Runner.",
    }
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"diagnosis={OUTPUT}; profiles={len(result['profiles'])}; function_local_parse=complete; translation_unit_parse=partial")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        raise SystemExit(2)
