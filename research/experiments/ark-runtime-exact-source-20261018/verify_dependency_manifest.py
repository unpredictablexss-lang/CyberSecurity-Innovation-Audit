#!/usr/bin/env python3
"""Read-only verifier for the bounded C-line exact-source dependency manifest."""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
MANIFEST = HERE / "dependency-manifest-v1.json"


def canonical(value: object) -> bytes:
    # UTF-8, JSON sorted keys, no insignificant whitespace, no ASCII escaping.
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def verify(path: Path) -> dict:
    manifest = json.loads(path.read_text(encoding="utf-8"))
    problems: list[str] = []
    for item in manifest["inputs"]:
        source = (ROOT / item["path"]).resolve()
        if ROOT.resolve() not in source.parents:
            problems.append(f"untrusted_path:{item['path']}")
            continue
        if not source.is_file():
            problems.append(f"missing_dependency:{item['path']}")
            continue
        actual = hashlib.sha256(source.read_bytes()).hexdigest()
        if actual != item["sha256"]:
            problems.append(f"dependency_hash_mismatch:{item['path']}")

    # The digest commits the complete declarative input set, including command,
    # macro/profile/tool metadata and explicit unresolved obligations.
    payload = {k: v for k, v in manifest.items() if k != "snapshot_sha256"}
    digest = hashlib.sha256(canonical(payload)).hexdigest()
    unresolved = manifest["dependency_closure"]["unresolved"]
    status = "blocked" if problems or unresolved or not manifest["dependency_closure"]["complete"] else "verified"
    return {"schema": "c-line-dependency-verification-v1", "status": status,
            "snapshot_sha256": digest, "manifest_digest_matches": digest == manifest.get("snapshot_sha256"),
            "input_count": len(manifest["inputs"]), "problems": sorted(problems),
            "unresolved_count": len(unresolved), "unresolved": unresolved}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--json", action="store_true", help="emit canonical machine-readable result")
    args = parser.parse_args()
    result = verify(args.manifest.resolve())
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))
    return 0 if result["status"] == "verified" and result["manifest_digest_matches"] else 2


if __name__ == "__main__":
    sys.exit(main())
