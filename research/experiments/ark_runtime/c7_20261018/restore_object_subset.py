"""Install and verify only the recovered historical Git objects used by C7.

The source packet remains outside the scanner repository; this tool adds only
the exact commit/tree/blob objects to a local bare object database.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from pathlib import Path


TARGET = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
SOURCES = {
    "c1_parent": ("c1_parent.cpp", "054451b1be4f39254d56a1683cc9d1c1b5e55018",
                  "847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422"),
    "c1_fix": ("c1_fix.cpp", "95f54f2875f401afe3167c62f8c1e7799782be8c",
               "8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e"),
    "c2_parent": ("exception_parent.cpp", "857ad416bc102fcd5d462e9702d2ba7c51f29b6d",
                  "984e45f2b6ea652c412437be03dda4189549afe4cf77c95713cf0d0c5d361db9"),
    "c2_fix": ("exception_fix.cpp", "3b9de9d915d767d7a67316145451da2446162884",
               "4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0"),
    "unrelated": ("holdout_95554.cpp", "e652d5e5ef1cec7176527f4d04023a8060abb5e9",
                  "db7856c17f46d4a6c9ac1e5114e72504c5487ace4cc92d70eacb8deaeb190fb4"),
}


def object_oid(kind: str, raw: bytes) -> str:
    header = kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\0"
    return hashlib.sha1(header + raw).hexdigest()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def git(repo: Path, *args: str, data: bytes | None = None) -> bytes:
    return subprocess.check_output(
        ["git", "--git-dir", str(repo), *args], input=data, stderr=subprocess.PIPE
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packet", type=Path, required=True,
                        help="Directory containing reconstructed_objects/ and the five verified .cpp blobs")
    parser.add_argument("--output-repo", type=Path, required=True,
                        help="New or existing local bare Git object database")
    parser.add_argument("--manifest", type=Path, required=True,
                        help="New JSON file to record installed and verified object identities")
    args = parser.parse_args()

    packet = args.packet.resolve()
    repo = args.output_repo.resolve()
    if not packet.is_dir():
        raise ValueError("source_packet_directory_missing")
    reconstruction = json.loads((packet / "reconstructed_objects" / "reconstruction_manifest.json").read_text(encoding="utf-8"))
    holdout = json.loads((packet / "holdout_95554_objects.json").read_text(encoding="utf-8"))
    if not repo.exists():
        repo.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "--bare", str(repo)], check=True,
                       stdout=subprocess.DEVNULL)
    if git(repo, "rev-parse", "--is-bare-repository").decode().strip() != "true":
        raise ValueError("output_git_repository_must_be_bare")

    installed = {"commits": [], "trees": [], "blobs": []}
    tree_dir = packet / "reconstructed_objects"
    expected_trees = {item["oid"] for item in reconstruction["trees"]}
    expected_trees.update(holdout["trees"].keys())
    for oid in sorted(expected_trees):
        raw = (tree_dir / (oid + ".tree")).read_bytes()
        if object_oid("tree", raw) != oid:
            raise ValueError("reconstructed_tree_oid_mismatch:" + oid)
        got = git(repo, "hash-object", "-t", "tree", "-w", "--stdin", data=raw).decode().strip()
        if got != oid:
            raise ValueError("installed_tree_oid_mismatch:" + oid)
        installed["trees"].append(oid)

    expected_commits = {item["oid"] for item in reconstruction["commits"]}
    expected_commits.add(holdout["commit"]["sha"])
    for oid in sorted(expected_commits):
        raw = (tree_dir / (oid + ".commit")).read_bytes()
        if object_oid("commit", raw) != oid:
            raise ValueError("reconstructed_commit_oid_mismatch:" + oid)
        got = git(repo, "hash-object", "-t", "commit", "-w", "--stdin", data=raw).decode().strip()
        if got != oid:
            raise ValueError("installed_commit_oid_mismatch:" + oid)
        installed["commits"].append(oid)

    for name, (filename, expected_blob, expected_sha) in SOURCES.items():
        raw = (packet / filename).read_bytes()
        got_blob = object_oid("blob", raw)
        got_sha = sha256(raw)
        if (got_blob, got_sha) != (expected_blob, expected_sha):
            raise ValueError(f"source_byte_binding_mismatch:{name}:{got_blob}:{got_sha}")
        installed_blob = git(repo, "hash-object", "-t", "blob", "-w", "--stdin", data=raw).decode().strip()
        if installed_blob != expected_blob:
            raise ValueError("installed_blob_oid_mismatch:" + name)
        installed["blobs"].append({"sample": name, "path": TARGET, "oid": got_blob,
                                   "source_sha256": got_sha, "bytes": len(raw)})

    bindings = []
    for item in reconstruction["commits"]:
        bindings.append({"commit": item["oid"], "tree": item["tree"], "parents": item["parents"]})
    bindings.append({"commit": holdout["commit"]["sha"],
                     "tree": holdout["commit"]["tree"]["sha"],
                     "parents": [parent["sha"] for parent in holdout["commit"]["parents"]]})
    for binding in bindings:
        raw = git(repo, "cat-file", "commit", binding["commit"])
        headers = raw.split(b"\n\n", 1)[0].decode("utf-8").splitlines()
        tree = next(line[5:] for line in headers if line.startswith("tree "))
        parents = [line[7:] for line in headers if line.startswith("parent ")]
        if tree != binding["tree"] or parents != binding["parents"]:
            raise ValueError("installed_commit_binding_mismatch:" + binding["commit"])
        binding["verified"] = True

    output = {
        "source_packet": str(packet),
        "declared_origin": reconstruction["source"],
        "repository": str(repo),
        "target_path": TARGET,
        "installed_counts": {key: len(value) for key, value in installed.items()},
        "objects": installed,
        "commit_bindings": bindings,
        "scope_note": "Exact target-path trees and blobs are verified. The packet does not include all unrelated subtrees, so it cannot provide whole-repository inventory.",
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"manifest": str(args.manifest.resolve()),
                      "installed_counts": output["installed_counts"]}, indent=2))


if __name__ == "__main__":
    main()
