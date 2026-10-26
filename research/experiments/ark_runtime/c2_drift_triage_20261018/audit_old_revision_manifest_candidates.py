#!/usr/bin/env python3
"""Audit a bounded set of locally available OpenHarmony manifest refs for C2's old Ark commit."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path


OLD_ARK_COMMIT = "a0e30483ab3e4aead67ecfb5c708489915e447f9"
CANDIDATE_REFS = (
    "OpenHarmony-v5.0.2-Release",
    "OpenHarmony-v5.0.3-Release",
    "OpenHarmony-v5.1.0-Release",
    "origin/OpenHarmony-5.0.2-Release",
    "origin/OpenHarmony-5.0.3-Release",
    "origin/114_trunk_5.0.3-Release",
    "origin/weekly_20241216",
    "origin/OpenHarmony_UIPlugin_20250323",
    "origin/OpenHarmony_feature_20250327",
    "origin/OpenHarmony_feature_20250328",
    "origin/114_trunk_feature_20250327",
    "origin/114_trunk_feature_20250328",
)


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(["git", "-C", str(repo), *args], check=check, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def text(repo: Path, *args: str) -> str:
    return git(repo, *args).stdout.decode("utf-8", errors="replace").strip()


def pin_from_xml(data: bytes) -> dict[str, str]:
    root = ET.fromstring(data)
    wanted = {
        "arkcompiler_ets_runtime": "arkcompiler/ets_runtime",
        "device_board_hihope": "device/board/hihope",
        "vendor_hihope": "vendor/hihope",
    }
    pins = {}
    for project in root.iter("project"):
        name = project.get("name", "")
        path = project.get("path", "")
        if name in wanted and path == wanted[name]:
            pins[name] = project.get("revision", "manifest-default")
    return pins


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--manifest-git", required=True, type=Path)
    ap.add_argument("--component-git", required=True, type=Path)
    ap.add_argument("--output", required=True, type=Path)
    ns = ap.parse_args()

    manifest_repo = ns.manifest_git.resolve()
    component_repo = ns.component_git.resolve()
    old_commit = text(component_repo, "show", "-s", "--format=%H", OLD_ARK_COMMIT)
    old_tree = text(component_repo, "show", "-s", "--format=%T", OLD_ARK_COMMIT)
    old_date = text(component_repo, "show", "-s", "--format=%cI", OLD_ARK_COMMIT)
    remote = text(manifest_repo, "remote", "get-url", "origin")
    remote_heads = git(manifest_repo, "ls-remote", "--heads", "origin").stdout.decode("utf-8", errors="replace").splitlines()
    remote_head_map = {line.split("\t", 1)[1].removeprefix("refs/heads/"): line.split("\t", 1)[0]
                       for line in remote_heads if "\t" in line}

    inspected = []
    for ref in CANDIDATE_REFS:
        commit = git(manifest_repo, "rev-parse", "--verify", f"{ref}^{{commit}}", check=False)
        if commit.returncode:
            inspected.append({"ref": ref, "status": "not_materialized_locally"})
            continue
        commit_id = commit.stdout.decode().strip()
        hit = git(manifest_repo, "grep", "-n", OLD_ARK_COMMIT, ref, "--", "*.xml", check=False)
        matching_manifest_lines = hit.stdout.decode("utf-8", errors="replace").splitlines()
        item = {"ref": ref, "manifest_commit": commit_id,
                "manifest_commit_date": text(manifest_repo, "show", "-s", "--format=%cI", commit_id),
                "old_ark_commit_pin_matches": matching_manifest_lines,
                "exact_old_commit_pinned": bool(matching_manifest_lines)}
        if ref == "OpenHarmony-v5.0.3-Release":
            candidate_file = "tag/manifest_tag_20250320_101213.xml"
            blob = git(manifest_repo, "show", f"{ref}:{candidate_file}", check=False)
            if blob.returncode == 0:
                pins = pin_from_xml(blob.stdout)
                candidate_ark = pins.get("arkcompiler_ets_runtime")
                ancestor = git(component_repo, "merge-base", "--is-ancestor", OLD_ARK_COMMIT,
                               candidate_ark or "", check=False)
                item["nearest_release_snapshot"] = {
                    "manifest_path": candidate_file,
                    "manifest_blob_sha256": hashlib.sha256(blob.stdout).hexdigest(),
                    "pins": pins,
                    "candidate_ark_commit_date": text(component_repo, "show", "-s", "--format=%cI", candidate_ark) if candidate_ark else None,
                    "old_commit_is_ancestor_of_candidate": ancestor.returncode == 0,
                }
        inspected.append(item)

    report = {
        "schema": "c2-old-revision-manifest-candidate-audit/v1",
        "captured_date": "2026-10-19",
        "scope": "bounded refs available locally plus current origin branch inventory; not an exhaustive search of every historical or third-party manifest",
        "old_ark_revision": {"commit": old_commit, "tree": old_tree, "commit_date": old_date},
        "manifest_remote": remote,
        "remote_heads_sha256": hashlib.sha256(("\n".join(remote_heads) + "\n").encode()).hexdigest(),
        "remote_heads_matching_release_or_march_candidates": {
            name: oid for name, oid in remote_head_map.items()
            if any(token in name for token in ("5.0.2", "5.0.3", "5.1.0", "202503", "weekly_202412"))
        },
        "inspected_refs": inspected,
        "conclusion": "No exact old Ark commit pin was found in the bounded candidate refs. The v5.0.3 release snapshot does pin HiHope board/vendor, but its Ark commit differs and is not the old commit's descendant; it is not a profile-matched old revision. A matching historical product manifest/profile remains unresolved.",
        "fail_closed": True,
    }
    ns.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"schema": report["schema"], "old_ark_commit": old_commit,
                      "checked_refs": len([x for x in inspected if x.get("status") != "not_materialized_locally"]),
                      "exact_pin_refs": [x["ref"] for x in inspected if x.get("exact_old_commit_pinned")],
                      "output": str(ns.output)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
