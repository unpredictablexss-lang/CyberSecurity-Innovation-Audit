from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


def git(git_dir: Path, *args: str, binary: bool = False):
    result = subprocess.run(
        ["git", f"--git-dir={git_dir}", *args],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return result if binary else result.decode("utf-8").strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", type=Path, required=True)
    parser.add_argument("--record", type=Path, default=Path(__file__).with_name(
        "a_t20_contacts_path_traversal_acceptance_20261020.json"))
    args = parser.parse_args()
    record = json.loads(args.record.read_text(encoding="utf-8"))
    source = record["source"]
    commit = source["commit"]
    path = source["path"]
    tree = git(args.git_dir, "rev-parse", f"{commit}^{{tree}}")
    blob = git(args.git_dir, "rev-parse", f"{commit}:{path}")
    raw = git(args.git_dir, "cat-file", "blob", blob, binary=True)
    actual = {
        "commit": commit,
        "tree": tree,
        "path": path,
        "blob": blob,
        "bytes": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }
    expected = {key: source[key] for key in actual}
    if actual != expected:
        raise SystemExit(json.dumps({"ok": False, "expected": expected, "actual": actual}, indent=2))
    print(json.dumps({"ok": True, **actual}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
