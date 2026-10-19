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


def git_repo(repo: Path, *args: str, binary: bool = False):
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        stdout=subprocess.PIPE,
    ).stdout
    return result if binary else result.decode("utf-8").strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", type=Path, required=True)
    parser.add_argument("--record", type=Path, default=Path(__file__).with_name(
        "a_t20_contacts_path_traversal_acceptance_20261020.json"))
    parser.add_argument("--scanner-repo", type=Path, default=Path(__file__).resolve().parents[3])
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

    replay = record["replay"]["independent_later_script_replay"]
    script_commit = replay["script_source_commit"]
    script_path = "research/evidence/cpp/contacts_path_traversal_20261019/direct_replay.py"
    script_blob = git_repo(args.scanner_repo, "rev-parse", f"{script_commit}:{script_path}")
    if script_blob != replay["script_blob"]:
        raise SystemExit(json.dumps({"ok": False, "script_blob_expected": replay["script_blob"],
                                     "script_blob_actual": script_blob}, indent=2))
    # Resolve the project-relative replay path from the repository root.
    replay_path = args.scanner_repo / replay["output"]
    replay_result = json.loads(replay_path.read_text(encoding="utf-8"))
    replay_identity = replay_result["git_object_identity"]
    locations = [finding["line"] for finding in replay_result["findings"]]
    if (replay_identity.get("commit") != source["commit"]
            or replay_identity.get("tree") != source["tree"]
            or replay_identity.get("blob") != source["blob"]
            or replay_result["source_sha256"] != source["sha256"]
            or replay_result["parse_status"] != "complete"
            or replay_result["parse_issue_count"] != 0
            or locations != [789, 790, 794]):
        raise SystemExit(json.dumps({"ok": False, "replay_identity": replay_identity,
                                     "replay_parse_status": replay_result["parse_status"],
                                     "replay_parse_issue_count": replay_result["parse_issue_count"],
                                     "candidate_locations": locations}, indent=2))
    print(json.dumps({"ok": True, **actual, "owner_review_script_commit": script_commit,
                      "owner_review_script_blob": script_blob, "secondary_replay_verified": True,
                      "candidate_locations": locations}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
