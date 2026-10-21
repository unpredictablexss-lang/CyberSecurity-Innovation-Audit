#!/usr/bin/env python3
"""Validate official parent archives and materialize isolated E2 Git databases.

The benchmark checkouts are shallow. This helper keeps them untouched and
builds separate bare repositories which borrow the pinned head objects through
Git alternates and contain the exact base commit/tree objects reconstructed
from official GitHub commit metadata and source archives. It refuses to run
unless both the reconstructed tree and commit object hashes match exactly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import tarfile
from datetime import datetime
from pathlib import Path


def git(repo: Path, *args: str, input_data: bytes | None = None) -> bytes:
    env = {**os.environ, "GIT_NO_LAZY_FETCH": "1", "GIT_TERMINAL_PROMPT": "0"}
    proc = subprocess.run(["git", "--git-dir", str(repo), *args], input=input_data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace")[-1500:])
    return proc.stdout


def oid(repo: Path, kind: str, payload: bytes) -> str:
    return git(repo, "hash-object", "-w", "-t", kind, "--stdin", input_data=payload).decode().strip()


def archive_objects(repo: Path, archive_path: Path) -> tuple[str, int, int]:
    root: dict = {}
    blob_count = 0
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive.getmembers():
            split = member.name.split("/", 1)
            if len(split) != 2 or not split[1]:
                continue
            parts = split[1].split("/")
            node = root
            for part in parts[:-1]:
                node = node.setdefault(part, {})
            if member.isdir():
                node.setdefault(parts[-1], {})
            elif member.isfile():
                stream = archive.extractfile(member)
                if stream is None:
                    raise ValueError(f"cannot read archive member: {member.name}")
                data = stream.read()
                node[parts[-1]] = ("100755" if member.mode & 0o111 else "100644",
                                   oid(repo, "blob", data))
                blob_count += 1
            elif member.issym():
                data = member.linkname.encode("utf-8")
                node[parts[-1]] = ("120000", oid(repo, "blob", data))
                blob_count += 1
            elif member.islnk():
                raise ValueError(f"unexpected hardlink in source archive: {member.name}")

    def write_tree(node: dict) -> str:
        entries = []
        for name, value in node.items():
            name_bytes = name.encode("utf-8")
            if isinstance(value, dict):
                mode, child_oid, sort_key = "40000", write_tree(value), name_bytes + b"/"
            else:
                mode, child_oid = value
                sort_key = name_bytes
            entries.append((sort_key, f"{mode} ".encode() + name_bytes + b"\0" + bytes.fromhex(child_oid)))
        payload = b"".join(item[1] for item in sorted(entries, key=lambda item: item[0]))
        return oid(repo, "tree", payload)

    return write_tree(root), blob_count, len(root)


def _epoch(date_value: str) -> int:
    return int(datetime.fromisoformat(date_value.replace("Z", "+00:00")).timestamp())


def commit_payload(metadata: dict) -> bytes:
    commit = metadata["commit"]
    expected = metadata["sha"]
    verification = commit.get("verification", {})
    signed_payload = verification.get("payload")
    candidates = []
    if signed_payload:
        unsigned = signed_payload.encode("utf-8")
        signature = verification.get("signature")
        if signature:
            headers, message = signed_payload.split("\n\n", 1)
            signature_lines = signature.rstrip("\n").splitlines()
            raw = (headers + "\ngpgsig " + signature_lines[0] + "\n" +
                   "\n".join(" " + line for line in signature_lines[1:]) +
                   "\n\n" + message).encode("utf-8")
            candidates.append(raw)
        candidates.append(unsigned)

    def identity(person: dict, offset: int) -> str:
        sign = "+" if offset >= 0 else "-"
        absolute = abs(offset)
        zone = f"{sign}{absolute // 60:02d}{absolute % 60:02d}"
        return f"{person['name']} <{person['email']}> {_epoch(person['date'])} {zone}"

    if not candidates:
        lines = [f"tree {commit['tree']['sha']}"]
        lines.extend(f"parent {parent['sha']}" for parent in metadata["parents"])
        message = commit["message"]
        # GitHub normalizes ISO dates to UTC; recover the original Git offsets
        # only by requiring the resulting object hash to equal the API SHA.
        for author_offset in range(-12 * 60, 14 * 60 + 1, 15):
            for committer_offset in (author_offset,):
                headers = [*lines, f"author {identity(commit['author'], author_offset)}",
                           f"committer {identity(commit['committer'], committer_offset)}"]
                for encoding in ("", "encoding UTF-8\n"):
                    for ending in ("", "\n"):
                        candidate = ("\n".join(headers) + "\n" + encoding + "\n" +
                                     message + ending).encode("utf-8")
                        candidates.append(candidate)
                        if hashlib.sha1(b"commit " + str(len(candidate)).encode() + b"\0" + candidate).hexdigest() == expected:
                            return candidate
        raise ValueError(f"cannot reproduce commit object SHA {expected} from official metadata")

    for candidate in candidates:
        actual = hashlib.sha1(b"commit " + str(len(candidate)).encode() + b"\0" + candidate).hexdigest()
        if actual == expected:
            return candidate
    raise ValueError(f"official commit payload does not hash to {expected}")


def build_one(entry: dict, source_root: Path, metadata_root: Path,
              secondary_metadata_root: Path, targets_root: Path) -> dict:
    label = entry["label"]
    repository = entry["repository"].split("/", 1)[1]
    folder = metadata_root / repository
    metadata = json.loads((folder / "commit.json").read_text(encoding="utf-8"))
    if metadata["sha"] != entry["base_commit"]:
        raise ValueError(f"{label}: official base SHA differs from manifest")
    source_repo = source_root / entry["repo_dir"]
    target_repo = targets_root / entry["repo_dir"]
    if target_repo.exists():
        raise FileExistsError(f"refusing to overwrite temporary target repo {target_repo}")
    target_repo.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", "--quiet", "--bare", str(target_repo)], check=True,
                   stdout=subprocess.DEVNULL)
    source_objects = subprocess.run(["git", "-C", str(source_repo), "rev-parse", "--absolute-git-dir"],
                                    check=True, capture_output=True, text=True).stdout.strip()
    alternates = target_repo / "objects" / "info" / "alternates"
    alternates.write_text(str(Path(source_objects) / "objects") + "\n", encoding="ascii")

    head_object = subprocess.run(["git", "-C", str(source_repo), "cat-file", "-p", entry["commit"]],
                                 check=True, capture_output=True, text=True).stdout
    head_parents = [line.split()[1] for line in head_object.splitlines() if line.startswith("parent ")]
    if not head_parents or head_parents[0] != metadata["sha"]:
        raise ValueError(f"{label}: official base is not the pinned head's first parent")

    tree_sha, blobs, root_dirs = archive_objects(target_repo, folder / "source.tar.gz")
    if tree_sha != metadata["commit"]["tree"]["sha"]:
        raise ValueError(f"{label}: archive tree {tree_sha} != official tree {metadata['commit']['tree']['sha']}")
    payload = commit_payload(metadata)
    commit_sha = oid(target_repo, "commit", payload)
    if commit_sha != metadata["sha"]:
        raise ValueError(f"{label}: reconstructed commit {commit_sha} != official SHA {metadata['sha']}")
    secondary_verified = []
    for secondary_sha in head_parents[1:]:
        secondary_path = secondary_metadata_root / repository / f"{secondary_sha}.json"
        secondary = json.loads(secondary_path.read_text(encoding="utf-8"))
        if secondary.get("sha") != secondary_sha:
            raise ValueError(f"{label}: secondary parent metadata SHA mismatch: {secondary_sha}")
        secondary_payload = commit_payload(secondary)
        actual_secondary = oid(target_repo, "commit", secondary_payload)
        if actual_secondary != secondary_sha:
            raise ValueError(f"{label}: secondary parent object SHA mismatch: {secondary_sha}")
        secondary_verified.append(secondary_sha)
    # The exact base is the shallow boundary for this fixed diff. Other merge
    # parents are also boundaries: their independent histories are irrelevant
    # to proving the base is the pinned head's first parent, and are not
    # represented as fetched history.
    shallow_boundaries = sorted({metadata["sha"], *secondary_verified})
    (target_repo / "shallow").write_text("".join(value + "\n" for value in shallow_boundaries),
                                         encoding="ascii")
    # The borrowed pinned-head objects remain in the original shallow checkout;
    # this isolated bare repo gains only exact base tree/blob/commit objects.
    git(target_repo, "update-ref", "refs/heads/pinned-head", entry["commit"])
    git(target_repo, "cat-file", "-e", entry["commit"] + "^{commit}")
    git(target_repo, "merge-base", "--is-ancestor", metadata["sha"], entry["commit"])
    changed = git(target_repo, "diff", "--name-only", "-M", "-z",
                  metadata["sha"], entry["commit"], "--")
    archive_digest = hashlib.sha256((folder / "source.tar.gz").read_bytes()).hexdigest()
    return {"label": label, "repository": entry["repository"], "base_commit": metadata["sha"],
            "head_commit": entry["commit"], "base_tree": tree_sha,
            "archive_sha256": archive_digest, "blobs": blobs, "top_level_entries": root_dirs,
            "base_commit_object_sha_verified": True, "base_tree_sha_verified": True,
            "head_first_parent_verified": True,
            "secondary_parent_objects_verified": secondary_verified,
            "secondary_histories_marked_shallow": bool(secondary_verified),
            "git_ancestor_check": True,
            "changed_path_count": len([x for x in changed.split(b"\0") if x]),
            "repository_path": str(target_repo)}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--metadata-root", type=Path, required=True)
    parser.add_argument("--secondary-metadata-root", type=Path, required=True)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--targets-root", type=Path, required=True)
    parser.add_argument("--evidence-out", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    rows = [build_one(entry, args.source_root, args.metadata_root,
                      args.secondary_metadata_root, args.targets_root)
            for entry in manifest["entries"]]
    evidence = {"schema_version": 1, "source_manifest": str(args.manifest), "rows": rows}
    args.evidence_out.parent.mkdir(parents=True, exist_ok=True)
    args.evidence_out.write_text(json.dumps(evidence, ensure_ascii=False, indent=2) + "\n",
                                 encoding="utf-8")
    print(json.dumps({"repositories": len(rows), "validated": sum(
        row["base_tree_sha_verified"] and row["base_commit_object_sha_verified"] and
        row["head_first_parent_verified"] and row["git_ancestor_check"] for row in rows),
        "evidence": str(args.evidence_out)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
