"""Read *pinned Git objects* from a local repository; no checkout, fetch or execution."""

from dataclasses import dataclass
import os
from pathlib import Path
import re
import subprocess
import urllib.parse

from .contracts import safe_relative_path

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
        lowered_message = message.lower()
        if (
            args
            and args[0] == "ls-tree"
            and (
                "lazy fetching disabled" in lowered_message
                or "could not fetch" in lowered_message
                or ("missing" in lowered_message and "object" in lowered_message)
            )
        ):
            raise ValueError(
                "missing_local_git_object: tree/entry object unavailable locally; "
                "offline-only read (no fetch). " + message
            )
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
    """Returns pinned commit/tree IDs, source objects, and a complete coverage inventory.

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
    }
    sources = []
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
        # With lazy fetching disabled, 'ls-tree -l' uses '-' for the size
        # of a missing local promisor blob. Fail explicitly; never fetch it.
        if size in ("-", "BAD"):
            # Git versions differ: some return '-' and others emit 'BAD'
            # for the missing size of an unfetched promisor object.
            raise ValueError("missing_local_git_object: blob unavailable locally "
                             + oid + " (" + path + "); offline-only read (no fetch)")
        if not size.isdecimal():
            raise ValueError("invalid blob size in Git tree")
        size_bytes = int(size)
        if size_bytes > MAX_BLOB_BYTES:
            inventory["oversize"] += 1
            inventory["skipped"].append({"file": path, "reason": "oversize"})
            continue
        if len(sources) >= MAX_SOURCE_FILES:
            raise ValueError("source file count exceeds M1 bounded scope")
        if inventory["selected_source_bytes"] + size_bytes > MAX_TOTAL_BYTES:
            raise ValueError("total source size exceeds M1 bounded scope")
        data = _git(repo, "cat-file", "blob", oid)
        if len(data) != size_bytes:
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

def verify_repository_identity(repo: Path, repository: str) -> str:
    """Verify that local ``origin`` names the declared public repository.

    The repository identity is not inferred from caller text alone. This check
    binds a pinned-object experiment to a recognized public host and an exact
    owner/repository path; it does not prove host ownership or build identity.
    """
    if repo.is_symlink() or not repo.is_dir():
        raise ValueError("source repository must be an existing non-symlink directory")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
        raise ValueError("invalid declared repository name")
    raw = _git(repo, "remote", "get-url", "origin").decode("utf-8", "replace").strip()
    if not raw or any(ord(char) < 32 for char in raw):
        raise ValueError("Git origin URL is missing or invalid")
    scp = re.fullmatch(r"(?:[^@/\s]+@)?([^:/\s]+):(.+)", raw)
    if "://" not in raw and scp:
        host, path = scp.group(1), scp.group(2)
    else:
        parsed = urllib.parse.urlparse(raw)
        if parsed.scheme not in ("https", "ssh") or not parsed.hostname or parsed.query or parsed.fragment:
            raise ValueError("Git origin must be an HTTPS or SSH public repository URL")
        host, path = parsed.hostname, parsed.path
    host = host.lower()
    if host not in {"github.com", "gitee.com", "gitcode.com", "gitlab.com"}:
        raise ValueError("Git origin host is not an accepted public repository host")
    normalized_path = path.strip("/").lower()
    if normalized_path.endswith(".git"):
        normalized_path = normalized_path[:-4]
    if normalized_path != repository.lower():
        raise ValueError("Git origin repository does not match the declared repository identity")
    return f"{host}:{normalized_path}"
