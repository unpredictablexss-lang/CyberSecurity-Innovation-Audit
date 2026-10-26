#!/usr/bin/env python3
"""Search the captured full manifest history for every old Ark commit in the C2 matrix."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[3]
MIRROR = Path("D:/openHarmonyScanner/tmp/c2-manifest-history-full-20261019.git")
MATRIX = HERE / "triage_matrix.json"
BASE_AUDIT = HERE / "full_manifest_history_audit_20261019.json"
OUT = HERE / "all_old_ark_manifest_pins_20261019.json"


def git(*args: str, check: bool = True) -> bytes:
    p = subprocess.run(["git", f"--git-dir={MIRROR}", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if check and p.returncode:
        raise RuntimeError(f"git {args!r} failed: {p.stderr.decode('utf-8', 'replace')}")
    return p.stdout


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    matrix_bytes = MATRIX.read_bytes()
    matrix = json.loads(matrix_bytes)
    old_commits = sorted({row["old"]["commit"] for row in matrix["dependencies"]})
    base = json.loads(BASE_AUDIT.read_text(encoding="utf-8"))
    bare = git("rev-parse", "--is-bare-repository").decode().strip() == "true"
    shallow = git("rev-parse", "--is-shallow-repository").decode().strip() == "true"
    remote = git("remote", "get-url", "origin").decode().strip()
    refs = git("for-each-ref", "--format=%(objectname) %(refname)")
    graph = git("rev-list", "--all", "--parents")
    searches = {}
    for commit in old_commits:
        data = git("log", "--all", "--full-history", "--format=%H%x09%cI%x09%s", f"-S{commit}", "--")
        searches[commit] = {
            "match_count": len(data.splitlines()),
            "matches_sha256": sha(data),
            "matches": data.decode("utf-8", "replace").splitlines(),
            "result": "no_exact_pin_in_reachable_advertised_history" if not data else "exact_pin_history_matches_found",
        }
    fsck = subprocess.run(["git", f"--git-dir={MIRROR}", "fsck", "--full", "--no-reflogs", "--connectivity-only"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    base_files = base["evidence_files"]
    captured_refs_match = sha(refs) == base_files["manifest_local_refs_full_20261019.txt"]["sha256"]
    captured_graph_match = sha(graph) == base_files["manifest_commit_graph_full_20261019.txt"]["sha256"]
    captured_fsck_match = sha(fsck.stdout) == base_files["manifest_mirror_fsck_20261019.log"]["sha256"]
    result = {
        "schema": "c2-all-old-ark-manifest-pins/v1",
        "old_ark_commits": old_commits,
        "old_commit_count": len(old_commits),
        "c2_dependency_rows_sha256": sha(json.dumps(matrix["dependencies"], ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")),
        "base_single_pin_audit_sha256": sha(BASE_AUDIT.read_bytes()),
        "remote": remote,
        "capture_scope": base["capture_scope"],
        "excluded_scope": base["excluded_scope"],
        "mirror": {
            "path": str(MIRROR), "bare": bare, "shallow": shallow,
            "ref_count": len(refs.splitlines()), "reachable_commit_count": len(graph.splitlines()),
            "ref_list_sha256": sha(refs), "commit_graph_sha256": sha(graph),
            "fsck_exit_code": fsck.returncode, "captured_ref_snapshot_matches": captured_refs_match,
            "captured_commit_graph_matches": captured_graph_match, "captured_fsck_output_matches": captured_fsck_match,
        },
        "searches": searches,
        "status": "complete_no_exact_pins_found" if bare and not shallow and remote == base["remote"] and fsck.returncode == 0 and captured_refs_match and captured_graph_match and captured_fsck_match and all(x["match_count"] == 0 for x in searches.values()) else "exact_pin_found_or_audit_incomplete",
    }
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "old_commit_count": len(old_commits), "match_counts": {k: v["match_count"] for k, v in searches.items()}, "reachable_commits": len(graph.splitlines()), "output": str(OUT)}, ensure_ascii=False, indent=2))
    return 0 if result["status"] == "complete_no_exact_pins_found" else 1


if __name__ == "__main__":
    raise SystemExit(main())
