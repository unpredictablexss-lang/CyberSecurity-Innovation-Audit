"""Read *pinned Git objects* from a local repository; no checkout, fetch or execution."""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess

from .contracts import safe_relative_path
from .git_batch import batch_blob_data

SOURCE_LANGUAGES = {
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".h": "cpp", ".hh": "cpp", ".hpp": "cpp",
    ".js": "js", ".ts": "ts", ".ets": "arkts",
}
MAX_BLOB_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_SOURCE_FILES = 2000


@dataclass(frozen=True)
class GitSource:
    path: str
    language: str
    oid: str
    data: bytes


def _git(repo: Path, *args: str, timeout: int = 30) -> bytes:
    environment = os.environ.copy()
    # A promisor/partial clone may auto-fetch missing objects even for cat-file.
    # Transport and lazy fetching MUST both be disabled, including with Git
    # versions that predate GIT_NO_LAZY_FETCH. No implicit network/local fetch.
    environment.update({
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_NO_LAZY_FETCH": "1",
        "GIT_ALLOW_PROTOCOL": "",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
    })
    # Match the no-promisor setting used by existing historical benchmark code.
    # An arbitrary additional promisor remote cannot transfer because all
    # transports are forbidden by GIT_ALLOW_PROTOCOL.
    process = subprocess.run(
        ["git", "-c", "remote.origin.promisor=false", "-C", str(repo), *args],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=environment, check=False, timeout=timeout,
    )
    if process.returncode:
        message = process.stderr.decode("utf-8", "replace")[:300]
        if args and args[0] == "cat-file" and args[1] == "blob":
            raise ValueError("missing_local_git_object_or_unreadable_blob: "
                             + args[2] + "; offline-only read (no fetch). " + message)
        raise ValueError(
            "Git object operation failed (" + " ".join(args[:2]) + "): " + message
        )
    return process.stdout


def resolve_commit(repo: Path, commit: str) -> tuple[str, str]:
    """Require a full SHA; do not accept moving refs or implicit HEAD."""
    if repo.is_symlink() or not repo.is_dir():
        raise ValueError("source repository must be an existing non-symlink directory")
    if not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", commit):
        raise ValueError("use a full lowercase Git commit SHA, not a branch or tag")
    resolved = _git(repo, "rev-parse", "--verify", commit + "^{commit}").decode().strip()
    if resolved != commit:
        raise ValueError("source commit must match the pinned full SHA")
    tree = _git(repo, "rev-parse", "--verify", commit + "^{tree}").decode().strip()
    return resolved, tree


def _within_scope(path: str, include_paths: tuple[str, ...]) -> bool:
    return any(item == "." or path == item or path.startswith(item + "/")
               for item in include_paths)


def load_git_sources(repo: Path, commit: str, includes: tuple[str, ...] = (".",)):
    """Return pinned commit/tree IDs, batch-read sources, and coverage inventory.

    Tracks supported source file entries in the Git tree. All other tracked
    entries are counted separately. Git symlinks/submodules are skipped.
    """
    if not includes or len(set(includes)) != len(includes):
        raise ValueError("include paths must be nonempty and distinct")
    for include in includes:
        if include != ".":
            safe_relative_path(include)
    pinned_commit, tree = resolve_commit(repo, commit)
    entries = _git(repo, "ls-tree", "-r", "-z", "-l", pinned_commit).split(b"\x00")
    inventory = {
        "tracked_entries": 0, "out_of_scope": 0, "non_source": 0,
        "symlinks": 0, "submodules": 0, "oversize": 0,
        "binary_or_non_utf8": 0, "selected_source_files": 0,
        "selected_source_bytes": 0, "skipped": [],
        "git_tree": tree, "declared_scope": list(includes),
        "git_blob_read_mode": "cat-file --batch",
    }
    pending: list[tuple[str, str, str, int]] = []
    pending_bytes = 0
    seen_paths = set()
    for raw in entries:
        if not raw:
            continue
        inventory["tracked_entries"] += 1
        try:
            metadata, path_bytes = raw.split(b"\t", 1)
            mode, kind, oid, size = metadata.decode("ascii").split()
            path = safe_relative_path(path_bytes.decode("utf-8"))
        except (ValueError, UnicodeError) as error:
            raise ValueError("malformed or unsafe Git tree entry") from error
        if path in seen_paths:
            raise ValueError("duplicate Git tree entry")
        seen_paths.add(path)
        if not _within_scope(path, includes):
            inventory["out_of_scope"] += 1
            continue
        if kind == "commit" or mode == "160000":
            inventory["submodules"] += 1
            continue
        if mode == "120000":
            inventory["symlinks"] += 1
            continue
        language = SOURCE_LANGUAGES.get(Path(path).suffix.lower())
        if language is None or kind != "blob":
            inventory["non_source"] += 1
            continue
        if not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", oid):
            raise ValueError("invalid object ID in Git tree")
        if size in ("-", "BAD"):
            raise ValueError("missing_local_git_object: blob unavailable locally "
                             + oid + " (" + path + "); offline-only read (no fetch)")
        if not size.isdecimal():
            raise ValueError("invalid blob size in Git tree")
        size_bytes = int(size)
        if size_bytes > MAX_BLOB_BYTES:
            inventory["oversize"] += 1
            inventory["skipped"].append({"file": path, "reason": "oversize"})
            continue
        if len(pending) >= MAX_SOURCE_FILES:
            raise ValueError("source file count exceeds M1 bounded scope")
        if inventory["selected_source_bytes"] + pending_bytes + size_bytes > MAX_TOTAL_BYTES:
            raise ValueError("total source size exceeds M1 bounded scope")
        pending_bytes += size_bytes
        pending.append((path, language, oid, size_bytes))

    blobs = batch_blob_data(repo, [item[2] for item in pending]) if pending else {}
    sources: list[GitSource] = []
    for path, language, oid, size_bytes in pending:
        info = blobs.get(oid, {"status": "missing_git_object"})
        if info.get("status") == "missing_git_object":
            raise ValueError("missing_local_git_object: blob unavailable locally "
                             + oid + " (" + path + "); offline-only read (no fetch)")
        if info.get("git_object_type") != "blob":
            raise ValueError("Git object is not a blob: " + path)
        data = info.get("data")
        if not isinstance(data, bytes) or len(data) != size_bytes:
            raise ValueError("Git blob size mismatch: " + path)
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            inventory["binary_or_non_utf8"] += 1
            inventory["skipped"].append({"file": path, "reason": "non_utf8"})
            continue
        sources.append(GitSource(path, language, oid, data))
        inventory["selected_source_bytes"] += size_bytes
    sources.sort(key=lambda value: value.path)
    inventory["selected_source_files"] = len(sources)
    if not sources:
        raise ValueError("no supported UTF-8 sources in selected Git scope")
    return pinned_commit, tree, tuple(sources), inventory
