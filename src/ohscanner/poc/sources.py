"""Materialise pinned component sources out of a local git object store.

The PoC must read the exact revision it claims, and third-party source must not
be committed to this repository (AGENTS.md). So the manifest carries
`(commit, path, sha256)` triples and this module copies the blobs out of a local
object store into a scratch directory, refusing to continue if a digest does not
match.
"""
from dataclasses import dataclass
import hashlib
from pathlib import Path
import subprocess


class SourceUnavailable(RuntimeError):
    """The pinned blob is not present in the local object store."""


class SourceMismatch(RuntimeError):
    """The blob read from the object store does not match the recorded digest."""


@dataclass(frozen=True)
class PinnedFile:
    commit: str
    path: str
    sha256: str
    revision: str = ""


def read_blob(git_dir, commit, path):
    """Raw bytes of `commit:path`, straight from the object store."""
    result = subprocess.run(
        ["git", "-C", str(git_dir), "cat-file", "blob", commit + ":" + path],
        capture_output=True, check=False)
    if result.returncode != 0:
        raise SourceUnavailable(
            "cannot read " + commit + ":" + path + " from " + str(git_dir) + ": "
            + result.stderr.decode("utf-8", errors="replace").strip())
    return result.stdout


def materialize(files, git_dir, destination):
    """Write every pinned file under `destination`, verifying its digest.

    Returns the written paths. Raises rather than proceeding when a blob is
    missing or has changed, so a PoC can never quietly run against a different
    revision than the one it reports.
    """
    destination = Path(destination)
    written = []
    for item in files:
        blob = read_blob(git_dir, item.commit, item.path)
        digest = hashlib.sha256(blob).hexdigest()
        if digest != item.sha256:
            raise SourceMismatch(
                "digest mismatch for " + item.path + " at " + item.commit
                + ": recorded " + item.sha256[:12] + ", read " + digest[:12])
        target = destination / item.path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(blob)
        written.append(target)
    return tuple(written)


def pinned_files(entries, *, revision_field=False):
    """Build PinnedFile records from a manifest's source/header lists."""
    files = []
    for entry in entries:
        files.append(PinnedFile(
            commit=entry["commit"], path=entry["path"], sha256=entry["sha256"],
            revision=entry.get("revision", "") if revision_field else ""))
    return tuple(files)
