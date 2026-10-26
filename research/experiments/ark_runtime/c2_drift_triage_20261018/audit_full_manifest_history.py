#!/usr/bin/env python3
"""Search all advertised OpenHarmony manifest refs and reachable history for C2's old Ark pin."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


OLD_ARK_COMMIT = "a0e30483ab3e4aead67ecfb5c708489915e447f9"
REMOTE = "https://gitcode.com/openharmony/manifest.git"


def run(args: list[str], *, check: bool = True) -> bytes:
    proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if check and proc.returncode:
        raise RuntimeError(f"{args!r} failed ({proc.returncode}): {proc.stderr.decode('utf-8', 'replace')}")
    return proc.stdout


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest-git", required=True, type=Path, help="Complete bare mirror of the manifest repository")
    ap.add_argument("--output-dir", type=Path, default=Path(__file__).parent)
    ns = ap.parse_args()
    repo = ns.manifest_git.resolve()
    out = ns.output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)

    bare = run(["git", f"--git-dir={repo}", "rev-parse", "--is-bare-repository"]).decode().strip() == "true"
    shallow = run(["git", f"--git-dir={repo}", "rev-parse", "--is-shallow-repository"]).decode().strip() == "true"
    remote = run(["git", f"--git-dir={repo}", "remote", "get-url", "origin"]).decode().strip()
    if not bare or shallow or remote != REMOTE:
        raise SystemExit(f"repository precondition failed: bare={bare}, shallow={shallow}, remote={remote}")

    advertised = run(["git", "ls-remote", "--refs", remote])
    local_refs = run(["git", f"--git-dir={repo}", "for-each-ref", "--format=%(objectname) %(refname)"])
    (out / "manifest_advertised_refs_full_20261019.txt").write_bytes(advertised)
    (out / "manifest_local_refs_full_20261019.txt").write_bytes(local_refs)

    advertised_map = {ref.decode(): oid.decode() for oid, ref in (line.split(b"\t", 1) for line in advertised.splitlines())}
    local_map = {ref.decode(): oid.decode() for oid, ref in (line.split(b" ", 1) for line in local_refs.splitlines())}
    ref_differences = {
        "remote_only": sorted(set(advertised_map) - set(local_map)),
        "local_only": sorted(set(local_map) - set(advertised_map)),
        "oid_mismatches": sorted(ref for ref in set(advertised_map) & set(local_map) if advertised_map[ref] != local_map[ref]),
    }

    graph = run(["git", f"--git-dir={repo}", "rev-list", "--all", "--parents"])
    (out / "manifest_commit_graph_full_20261019.txt").write_bytes(graph)
    search = run(["git", f"--git-dir={repo}", "log", "--all", "--full-history", "--format=%H%x09%cI%x09%s", f"-S{OLD_ARK_COMMIT}", "--"])
    (out / "manifest_old_ark_pin_history_matches_20261019.txt").write_bytes(search)
    fsck = subprocess.run(
        ["git", f"--git-dir={repo}", "fsck", "--full", "--no-reflogs", "--connectivity-only"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False,
    )
    (out / "manifest_mirror_fsck_20261019.log").write_bytes(fsck.stdout)

    graph_lines = graph.splitlines()
    report = {
        "schema": "c2-full-manifest-history-pin-audit/v1",
        "old_ark_commit": OLD_ARK_COMMIT,
        "remote": remote,
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "capture_scope": "all refs advertised by git ls-remote --refs at capture and the complete parent/blob history reachable from those refs in the non-shallow mirror",
        "excluded_scope": "unadvertised or unreachable server objects and third-party manifest repositories",
        "mirror": {
            "path": str(repo), "bare": bare, "shallow": shallow,
            "local_ref_count": len(local_map), "reachable_commit_count": len(graph_lines),
            "advertised_ref_count": len(advertised_map),
            "all_advertised_refs_materialized_at_capture": not any(ref_differences.values()),
            "ref_differences": ref_differences,
            "fsck_exit_code": fsck.returncode,
        },
        "historical_exact_pin_search": {
            "command": "git log --all --full-history --format=%H%x09%cI%x09%s -S<old-commit> --",
            "match_count": len(search.splitlines()),
            "matches_sha256": sha(search),
            "result": "no_exact_pin_in_reachable_advertised_history" if not search else "exact_pin_history_matches_found",
        },
        "evidence_files": {
            name: {"sha256": sha((out / name).read_bytes()), "bytes": (out / name).stat().st_size}
            for name in (
                "manifest_advertised_refs_full_20261019.txt",
                "manifest_local_refs_full_20261019.txt",
                "manifest_commit_graph_full_20261019.txt",
                "manifest_old_ark_pin_history_matches_20261019.txt",
                "manifest_mirror_fsck_20261019.log",
            )
        },
    }
    report["status"] = "complete_no_exact_pin_found" if (
        not search and not any(ref_differences.values()) and fsck.returncode == 0
    ) else "blocked_or_exact_match_found"
    result_path = out / "full_manifest_history_audit_20261019.json"
    result_path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "advertised_refs": len(advertised_map),
                      "local_refs": len(local_map), "reachable_commits": len(graph_lines),
                      "history_matches": len(search.splitlines()), "output": str(result_path)},
                     ensure_ascii=False, indent=2))
    return 0 if report["status"] == "complete_no_exact_pin_found" else 1


if __name__ == "__main__":
    raise SystemExit(main())
