"""Read *pinned Git objects* from a local repository; no checkout, fetch or execution."""

from dataclasses import dataclass
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import zlib

from .contracts import safe_relative_path

SOURCE_LANGUAGES = {
    ".c": "c", ".cc": "cpp", ".cpp": "cpp", ".cxx": "cpp",
    ".h": "cpp", ".hh": "cpp", ".hpp": "cpp",
    ".js": "js", ".ts": "ts", ".ets": "arkts",
}
MAX_BLOB_BYTES = 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_SOURCE_FILES = 2000
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 16 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 2000
ARCHIVE_SUFFIXES = (".tar.gz", ".tgz")


@dataclass(frozen=True)
class GitSource:
    path: str
    language: str
    oid: str
    data: bytes
    archive_binding: dict | None = None


def _archive_member_sources(path: str, archive_oid: str, archive_data: bytes):
    """Read bounded regular C/C++ members without extracting files to disk."""
    sources, skipped = [], []
    expanded = members = 0
    problem = None
    try:
        archive = tarfile.open(fileobj=io.BytesIO(archive_data), mode="r|gz")
        with archive:
            for member in archive:
                members += 1
                if members > MAX_ARCHIVE_MEMBERS:
                    problem = "archive member count exceeds bounded scope"
                    break
                if member.size < 0:
                    problem = "archive member has invalid size"
                    break
                expanded += member.size
                if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                    problem = "archive expanded size exceeds bounded scope"
                    break
                if not member.isfile():
                    if member.issym() or member.islnk():
                        skipped.append({"member": member.name[:240], "reason": "link_member"})
                    continue
                try:
                    member_path = safe_relative_path(member.name)
                except ValueError:
                    skipped.append({"member": member.name[:240], "reason": "unsafe_path"})
                    continue
                language = SOURCE_LANGUAGES.get(Path(member_path).suffix.lower())
                if language is None:
                    continue
                if member.size > MAX_BLOB_BYTES:
                    skipped.append({"member": member_path, "reason": "oversize"})
                    continue
                try:
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ValueError("archive source member could not be read")
                    data = stream.read(MAX_BLOB_BYTES + 1)
                    if len(data) != member.size:
                        raise ValueError("archive source member size mismatch")
                    data.decode("utf-8")
                    virtual_path = safe_relative_path(path + ".members/" + member_path)
                except (ValueError, UnicodeDecodeError, OSError) as error:
                    skipped.append({"member": member_path, "reason": "invalid_member"})
                    problem = str(error)[:200]
                    break
                binding = {"archive_path": path, "archive_blob_oid": archive_oid,
                           "archive_sha256": hashlib.sha256(archive_data).hexdigest(),
                           "member_path": member_path,
                           "member_sha256": hashlib.sha256(data).hexdigest()}
                # Internal content identity only; this is not a tracked Git blob.
                member_oid = hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
                sources.append(GitSource(virtual_path, language, member_oid, data, binding))
    except (tarfile.TarError, EOFError, OSError, ValueError, zlib.error) as error:
        problem = str(error)[:200] or "tracked source archive is invalid or truncated"
    return tuple(sources), {"members_seen": members, "expanded_bytes": expanded,
                            "selected_sources": len(sources), "skipped": skipped,
                            "oversize": sum(item["reason"] == "oversize" for item in skipped),
                            "binary_or_non_utf8": sum(item["reason"] == "non_utf8" for item in skipped),
                            "status": "partial" if problem else "indexed",
                            "limitations": [problem] if problem else []}


def _git(repo: Path, *args: str, timeout: int = 30) -> bytes:
    environment = _git_environment()
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


def _git_environment() -> dict[str, str]:
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
    return environment


def _git_batch_blobs(
    repo: Path, blobs: tuple[tuple[str, str, int], ...], timeout: int = 30,
) -> tuple[bytes, ...]:
    """Read a bounded group of pinned blobs with one Git process."""
    if not blobs:
        return ()
    request = b"".join(oid.encode("ascii") + b"\n" for _, oid, _ in blobs)
    process = subprocess.run(
        ["git", "-c", "remote.origin.promisor=false", "-C", str(repo),
         "cat-file", "--batch"],
        input=request, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env=_git_environment(), check=False, timeout=timeout,
    )
    if process.returncode:
        message = process.stderr.decode("utf-8", "replace")[:300]
        raise ValueError("Git batch object operation failed (cat-file --batch): " + message)

    output = process.stdout
    offset = 0
    contents = []
    for path, oid, expected_size in blobs:
        header_end = output.find(b"\n", offset)
        if header_end < 0:
            raise ValueError("truncated Git batch response header: " + path)
        header = output[offset:header_end].split()
        if len(header) == 2 and header[1] == b"missing":
            raise ValueError("missing_local_git_object_or_unreadable_blob: "
                             + oid + "; offline-only read (no fetch).")
        if len(header) != 3:
            raise ValueError("malformed Git batch response header: " + path)
        returned_oid, object_type, size_bytes = header
        if returned_oid.decode("ascii", "replace") != oid or object_type != b"blob":
            raise ValueError("Git batch returned an unexpected object: " + path)
        if not size_bytes.isdigit() or int(size_bytes) != expected_size:
            raise ValueError("Git blob size mismatch: " + path)
        start = header_end + 1
        end = start + expected_size
        if end >= len(output) or output[end:end + 1] != b"\n":
            raise ValueError("truncated Git batch blob data: " + path)
        contents.append(output[start:end])
        offset = end + 1
    if offset != len(output):
        raise ValueError("unexpected trailing data in Git batch response")
    return tuple(contents)


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
        "git_tree": tree, "declared_scope": list(includes), "source_archives": [],
    }
    source_entries = []
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
        is_archive = path.lower().endswith(ARCHIVE_SUFFIXES)
        language = SOURCE_LANGUAGES.get(Path(path).suffix.lower())
        if is_archive:
            if not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", oid):
                raise ValueError("invalid object ID in Git tree")
            if size in ("-", "BAD"):
                raise ValueError("missing_local_git_object: archive unavailable locally " + oid)
            if not size.isdecimal():
                raise ValueError("invalid archive size in Git tree")
            size_bytes = int(size)
            if size_bytes > MAX_ARCHIVE_BYTES:
                inventory["oversize"] += 1
                inventory["skipped"].append({"file": path, "reason": "oversize_archive"})
                inventory["source_archives"].append({"archive": path, "status": "skipped_oversize"})
                continue
            source_entries.append((path, "__archive__", oid, size_bytes))
            continue
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
        source_entries.append((path, language, oid, size_bytes))

    sources = []
    start = 0
    while start < len(source_entries):
        end = start
        batch_bytes = 0
        while end < len(source_entries) and end - start < 512:
            next_size = source_entries[end][3]
            if end > start and batch_bytes + next_size > MAX_TOTAL_BYTES:
                break
            batch_bytes += next_size
            end += 1
        batch = source_entries[start:end]
        requests = tuple((path, oid, size_bytes)
                         for path, _, oid, size_bytes in batch)
        data_items = _git_batch_blobs(repo, requests)
        for (path, language, oid, size_bytes), data in zip(batch, data_items):
            if language == "__archive__":
                extracted, archive_info = _archive_member_sources(path, oid, data)
                inventory["source_archives"].append({
                    "archive": path, "archive_blob_oid": oid,
                    "archive_sha256": hashlib.sha256(data).hexdigest(),
                    **archive_info,
                })
                inventory["oversize"] += archive_info["oversize"]
                inventory["binary_or_non_utf8"] += archive_info["binary_or_non_utf8"]
                inventory["skipped"].extend(
                    {"file": path + ".members/" + item["member"], "reason": item["reason"]}
                    for item in archive_info["skipped"] if item["reason"] in ("oversize", "non_utf8")
                )
                for source in extracted:
                    if len(sources) >= MAX_SOURCE_FILES:
                        raise ValueError("source file count exceeds M1 bounded scope")
                    if inventory["selected_source_bytes"] + len(source.data) > MAX_TOTAL_BYTES:
                        raise ValueError("total source size exceeds M1 bounded scope")
                    sources.append(source)
                    inventory["selected_source_bytes"] += len(source.data)
                continue
            if len(sources) >= MAX_SOURCE_FILES:
                raise ValueError("source file count exceeds M1 bounded scope")
            if inventory["selected_source_bytes"] + size_bytes > MAX_TOTAL_BYTES:
                raise ValueError("total source size exceeds M1 bounded scope")
            try:
                data.decode("utf-8")
            except UnicodeDecodeError:
                inventory["binary_or_non_utf8"] += 1
                inventory["skipped"].append({"file": path, "reason": "non_utf8"})
                continue
            sources.append(GitSource(path, language, oid, data))
            inventory["selected_source_bytes"] += size_bytes
        start = end
    sources.sort(key=lambda value: value.path)
    inventory["selected_source_files"] = len(sources)
    if not sources:
        raise ValueError("no supported UTF-8 sources in selected Git scope")
    return pinned_commit, tree, tuple(sources), inventory
