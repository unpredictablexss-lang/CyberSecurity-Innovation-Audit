#!/usr/bin/env python3
"""Read-only canonical profile digest and fail-closed readiness check."""

import argparse
import hashlib
import json
import sys
from pathlib import Path


REQUIRED = (
    "compiler_path",
    "compiler_version",
    "target_triple",
    "working_directory",
    "command_argv",
    "defines",
    "include_search_order",
    "generated_inputs",
    "dependency_closure",
    "compile_database",
    "gn_args",
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", nargs="?", default=str(Path(__file__).with_name("profile_manifest.json")))
    parser.add_argument("--expected-digest", help="previous canonical profile digest")
    args = parser.parse_args()
    data = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    digest = hashlib.sha256(encoded).hexdigest()
    print(f"profile_sha256={digest}")
    if args.expected_digest and digest != args.expected_digest.lower():
        print("BLOCKED: profile digest mismatch", file=sys.stderr)
        return 3
    workspace_parent = Path(__file__).resolve().parents[5]
    mismatches = []
    for item in data.get("input_file_checks", []):
        path = workspace_parent / item["path_from_workspace_parent"]
        if not path.is_file():
            mismatches.append(f"missing:{item['path_from_workspace_parent']}")
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != item["sha256"].lower():
            mismatches.append(f"sha256:{item['path_from_workspace_parent']}")
    if mismatches:
        print("BLOCKED: pinned input mismatch=" + ",".join(mismatches), file=sys.stderr)
        return 4
    missing = [key for key in REQUIRED if data.get("translation_unit_profile", {}).get(key) in (None, "", [])]
    if data.get("status") != "ready" or data.get("translation_unit_profile", {}).get("status") != "ready" or missing:
        print("BLOCKED: exact product build profile is incomplete; missing=" + ",".join(missing), file=sys.stderr)
        return 2
    print("READY: profile fields are populated; this check does not compile or preprocess the source")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
