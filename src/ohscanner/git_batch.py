"""Offline batched Git object reads for source-bound scans."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
import subprocess
from typing import Any, Mapping, Sequence

from .contracts import safe_relative_path

_OID = re.compile(r"[a-f0-9]{40}|[a-f0-9]{64}")


def offline_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update({
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    return env


def offline_git(repo: Path, *args: str, timeout: int = 30) -> bytes:
    process = subprocess.run(
        ["git", "-c", "remote.origin.promisor=false", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=offline_env(),
        check=False,
        timeout=timeout,
    )
    if process.returncode:
        detail = process.stderr.decode("utf-8", "replace")[:300]
        if args and args[0] == "cat-file" and args[1] == "blob":
            raise ValueError(
                "missing_local_git_object_or_unreadable_blob: "
                + args[2] + "; offline-only read (no fetch). " + detail
            )
        raise ValueError(
            "Git object operation failed (" + " ".join(args[:2]) + "): " + detail
        )
    return process.stdout


def _chunks(values: Sequence[str], size: int) -> list[list[str]]:
    return [list(values[index:index + size]) for index in range(0, len(values), size)]


def _parse_ls_tree(raw: bytes, revision: str, requested: set[str]) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for item in raw.split(b"\x00"):
        if not item:
            continue
        metadata, path_raw = item.split(b"\t", 1)
        mode, kind, oid = metadata.decode("ascii").split()
        path = safe_relative_path(path_raw.decode("utf-8"))
        if path not in requested:
            raise ValueError("Git batch tree returned an unexpected path")
        result[path] = {
            "revision": revision,
            "mode": mode,
            "kind": kind,
            "source_blob_oid": oid,
        }
    return result


def _parse_cat_file_batch(raw: bytes) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    offset = 0
    while offset < len(raw):
        end = raw.find(b"\n", offset)
        if end < 0:
            raise ValueError("malformed git cat-file --batch output")
        header = raw[offset:end].decode("ascii", "replace")
        offset = end + 1
        fields = header.split()
        if len(fields) == 2 and fields[1] == "missing":
            result[fields[0]] = {"status": "missing_git_object"}
            continue
        if len(fields) != 3:
            raise ValueError("malformed git cat-file --batch header")
        oid, kind, size_text = fields
        if not _OID.fullmatch(oid) or not size_text.isdecimal():
            raise ValueError("invalid git cat-file --batch object header")
        size = int(size_text)
        data = raw[offset:offset + size]
        if len(data) != size or offset + size >= len(raw) or raw[offset + size] != 0x0A:
            raise ValueError("truncated git cat-file --batch object")
        offset += size + 1
        result[oid] = {
            "status": "bound",
            "git_object_type": kind,
            "source_bytes": size,
            "source_sha256": hashlib.sha256(data).hexdigest(),
            "source_lines": len(data.splitlines()),
            "data": data,
        }
    return result


def batch_blob_identities(
    repo: Path,
    requests: Sequence[tuple[str, str]],
    *,
    max_paths_per_command: int = 256,
    max_objects_per_batch: int = 256,
) -> dict[tuple[str, str], dict[str, Any]]:
    """Resolve exact tree entries and blobs with bounded local-only batch Git."""
    if max_paths_per_command < 1 or max_objects_per_batch < 1:
        raise ValueError("Git batch limits must be positive")
    grouped: dict[str, set[str]] = {}
    for revision, path in requests:
        safe_relative_path(path)
        grouped.setdefault(revision, set()).add(path)
    entries: dict[tuple[str, str], dict[str, Any]] = {}
    object_requests: dict[str, list[tuple[str, str]]] = {}
    for revision in sorted(grouped):
        paths = sorted(grouped[revision])
        for chunk in _chunks(paths, max_paths_per_command):
            raw = offline_git(
                repo,
                "ls-tree",
                "-z",
                revision,
                "--",
                *chunk,
            )
            rows = _parse_ls_tree(raw, revision, set(chunk))
            for path in chunk:
                row = rows.get(path)
                key = (revision, path)
                if row is None:
                    entries[key] = {
                        "status": "absent",
                        "revision": revision,
                        "source_blob_oid": None,
                        "source_sha256": None,
                        "source_bytes": None,
                        "source_lines": None,
                    }
                    continue
                if row["kind"] != "blob" or row["mode"] == "160000":
                    entries[key] = {
                        "status": "not_blob",
                        "revision": revision,
                        "git_object_type": row["kind"],
                        "mode": row["mode"],
                        "source_blob_oid": row["source_blob_oid"],
                        "source_sha256": None,
                        "source_bytes": None,
                        "source_lines": None,
                    }
                    continue
                if row["mode"] == "120000":
                    entries[key] = {
                        "status": "symlink",
                        "revision": revision,
                        "git_object_type": row["kind"],
                        "mode": row["mode"],
                        "source_blob_oid": row["source_blob_oid"],
                        "source_sha256": None,
                        "source_bytes": None,
                        "source_lines": None,
                    }
                    continue
                object_requests.setdefault(row["source_blob_oid"], []).append(key)

    objects: dict[str, dict[str, Any]] = {}
    for chunk in _chunks(sorted(object_requests), max_objects_per_batch):
        payload = ("\n".join(chunk) + "\n").encode("ascii")
        process = subprocess.run(
            [
                "git",
                "-c",
                "remote.origin.promisor=false",
                "-C",
                str(repo),
                "cat-file",
                "--batch",
            ],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=offline_env(),
            check=False,
            timeout=60,
        )
        if process.returncode:
            raise ValueError(
                "offline git cat-file batch failed: "
                + process.stderr.decode("utf-8", "replace")[:300]
            )
        objects.update(_parse_cat_file_batch(process.stdout))

    for oid, keys in object_requests.items():
        info = objects.get(oid, {"status": "missing_git_object"})
        for key in keys:
            revision, path = key
            entries[key] = {
                "status": info["status"],
                "revision": revision,
                "source_blob_oid": oid,
                "source_sha256": info.get("source_sha256"),
                "source_bytes": info.get("source_bytes"),
                "source_lines": info.get("source_lines"),
            }
            if info.get("git_object_type") not in (None, "blob"):
                entries[key]["status"] = "not_blob"
                entries[key]["git_object_type"] = info["git_object_type"]
    return entries

def batch_blob_data(
    repo: Path,
    oids: Sequence[str],
    *,
    max_objects_per_batch: int = 256,
) -> dict[str, dict[str, Any]]:
    """Read exact blob bytes in bounded local-only cat-file batches."""
    if max_objects_per_batch < 1:
        raise ValueError("max_objects_per_batch must be positive")
    unique = sorted(set(oids))
    for oid in unique:
        if not _OID.fullmatch(oid):
            raise ValueError("invalid Git blob OID")
    result: dict[str, dict[str, Any]] = {}
    for chunk in _chunks(unique, max_objects_per_batch):
        payload = ("\n".join(chunk) + "\n").encode("ascii")
        process = subprocess.run(
            [
                "git",
                "-c",
                "remote.origin.promisor=false",
                "-C",
                str(repo),
                "cat-file",
                "--batch",
            ],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=offline_env(),
            check=False,
            timeout=60,
        )
        if process.returncode:
            raise ValueError(
                "offline git cat-file batch failed: "
                + process.stderr.decode("utf-8", "replace")[:300]
            )
        for oid, info in _parse_cat_file_batch(process.stdout).items():
            result[oid] = {
                key: value for key, value in info.items() if key != "data"
            } | {"data": info.get("data")}
    return result
