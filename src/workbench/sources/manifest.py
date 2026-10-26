"""Small immutable planning inputs, independent of scanning and persistence.

A manifest binds supplied identities; it does not authenticate an official
remote, load a repository, or prove that a language frontend is complete.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import re

from src.ohscanner.contracts import ScanContext, safe_relative_path
from src.ohscanner.fixture import snapshot_digest


def canonical_sha256(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=False, allow_nan=False).encode()).hexdigest()


@dataclass(frozen=True)
class SourceFile:
    path: str
    language: str
    sha256: str
    parse_status: str = "not_run"
    blob_oid: str | None = None

    def __post_init__(self):
        safe_relative_path(self.path)
        if not isinstance(self.language, str) or not re.fullmatch(r"[a-z][a-z0-9_+-]{0,31}", self.language):
            raise ValueError("invalid declared language")
        if not isinstance(self.sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", self.sha256):
            raise ValueError("invalid source SHA-256")
        if self.parse_status not in ("complete", "partial", "failed", "not_run"):
            raise ValueError("invalid parse status")
        if self.blob_oid is not None and not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", self.blob_oid):
            raise ValueError("invalid blob ID")


@dataclass(frozen=True)
class SourceManifest:
    repository: str
    commit: str
    git_tree: str
    snapshot_sha256: str
    files: tuple[SourceFile, ...]
    include_paths: tuple[str, ...] = (".",)
    available_facts: tuple[str, ...] = ()
    unclassified_entries: int = 0
    skipped_entries: int = 0
    skipped_files: tuple[tuple[str, str], ...] = ()
    provenance: str = "caller_supplied"
    profile_id: str = "light-ast"

    def __post_init__(self):
        if not isinstance(self.repository, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", self.repository):
            raise ValueError("invalid declared repository")
        for value in (self.commit, self.git_tree):
            if not isinstance(value, str) or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", value):
                raise ValueError("full pinned commit/tree IDs required")
        if len(self.commit) != len(self.git_tree):
            raise ValueError("mixed Git object formats")
        if not isinstance(self.files, tuple) or not all(isinstance(f, SourceFile) for f in self.files):
            raise ValueError("immutable source files required")
        if any(f.blob_oid is not None and len(f.blob_oid) != len(self.commit) for f in self.files):
            raise ValueError("mixed blob object format")
        if len({f.path for f in self.files}) != len(self.files):
            raise ValueError("duplicate source path")
        expected = snapshot_digest(sorted(self.files, key=lambda f: f.path))
        if self.snapshot_sha256 != expected:
            raise ValueError("source manifest snapshot mismatch")
        if not isinstance(self.include_paths, tuple) or not self.include_paths or len(set(self.include_paths)) != len(self.include_paths):
            raise ValueError("distinct nonempty include paths required")
        for path in self.include_paths:
            if path != ".":
                safe_relative_path(path)
        if any(not any(p == "." or f.path == p or f.path.startswith(p + "/")
                       for p in self.include_paths) for f in self.files):
            raise ValueError("source file outside declared scope")
        if not isinstance(self.available_facts, tuple) or not all(isinstance(f, str) and f for f in self.available_facts):
            raise ValueError("invalid available facts")
        for count in (self.unclassified_entries, self.skipped_entries):
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("invalid inventory count")
        if not isinstance(self.skipped_files, tuple):
            raise ValueError("immutable skipped file records required")
        skipped_paths = set()
        for record in self.skipped_files:
            if (not isinstance(record, tuple) or len(record) != 2
                    or not isinstance(record[1], str) or not record[1].strip()):
                raise ValueError("invalid skipped file record")
            path, _ = record
            safe_relative_path(path)
            if path in skipped_paths or any(f.path == path for f in self.files):
                raise ValueError("duplicate or selected skipped file")
            if not any(p == "." or path == p or path.startswith(p + "/") for p in self.include_paths):
                raise ValueError("skipped file outside declared scope")
            skipped_paths.add(path)
        if len(skipped_paths) > self.skipped_entries:
            raise ValueError("skipped records exceed skipped count")
        if self.provenance not in ("caller_supplied", "context_snapshot_checked"):
            raise ValueError("unknown manifest provenance")
        if not isinstance(self.profile_id, str) or not self.profile_id:
            raise ValueError("missing index profile")

    def to_dict(self):
        result = asdict(self)
        result["files"] = [asdict(f) for f in sorted(self.files, key=lambda f: f.path)]
        result["include_paths"] = sorted(self.include_paths)
        result["available_facts"] = sorted(set(self.available_facts))
        result["skipped_files"] = [{"file": p, "reason": reason} for p, reason in sorted(self.skipped_files)]
        return result


def manifest_from_context(context: ScanContext, git_tree: str, inventory: dict,
                          sources=None) -> SourceManifest:
    """Adapt prepare_git_context output, without further I/O or parser execution.

    Optional GitSource objects bind blob IDs after content equality checks.
    The existing engine remains responsible for reading/rechecking Git objects.
    """
    if context.request.provenance != "git_object":
        raise ValueError("fixed Git context required; fixture is not product provenance")
    if snapshot_digest(context.units) != context.request.snapshot_sha256:
        raise ValueError("context snapshot mismatch")
    if inventory.get("git_tree") != git_tree:
        raise ValueError("inventory tree mismatch")
    names = ("tracked_entries", "out_of_scope", "non_source", "symlinks", "submodules",
             "oversize", "binary_or_non_utf8", "selected_source_files", "selected_source_bytes")
    if any(isinstance(inventory.get(k), bool) or not isinstance(inventory.get(k), int)
           or inventory[k] < 0 for k in names):
        raise ValueError("missing or invalid source inventory counts")
    if inventory["selected_source_files"] != len(context.units):
        raise ValueError("inventory file count mismatch")
    if inventory["selected_source_bytes"] != sum(len(u.text.encode("utf-8")) for u in context.units):
        raise ValueError("inventory byte count mismatch")
    if inventory["tracked_entries"] != sum(inventory[k] for k in names[1:-1]):
        raise ValueError("inventory counts do not close")
    skipped = inventory.get("skipped", [])
    if not isinstance(skipped, list) or any(
            not isinstance(item, dict) or item.get("reason") not in ("oversize", "non_utf8")
            or not isinstance(item.get("file"), str) for item in skipped):
        raise ValueError("invalid skipped inventory records")
    if (sum(item["reason"] == "oversize" for item in skipped) != inventory["oversize"]
            or sum(item["reason"] == "non_utf8" for item in skipped) != inventory["binary_or_non_utf8"]):
        raise ValueError("skipped inventory records/counts mismatch")
    blobs = {}
    if sources is not None:
        supplied = tuple(sources)
        if len(supplied) != len(context.units) or len({s.path for s in supplied}) != len(supplied):
            raise ValueError("source object inventory mismatch")
        by_path = {s.path: s for s in supplied}
        for unit in context.units:
            source = by_path.get(unit.path)
            if source is None or source.language != unit.language or source.data != unit.text.encode("utf-8"):
                raise ValueError("Git source/context content mismatch")
            blob = b"blob " + str(len(source.data)).encode() + b"\0" + source.data
            digest = hashlib.sha1(blob).hexdigest() if len(context.request.commit) == 40 else hashlib.sha256(blob).hexdigest()
            if digest != source.oid:
                raise ValueError("Git blob identity/content mismatch")
            blobs[unit.path] = source.oid
    return SourceManifest(
        repository=context.request.repository, commit=context.request.commit,
        git_tree=git_tree, snapshot_sha256=context.request.snapshot_sha256,
        files=tuple(SourceFile(u.path, u.language, u.sha256, u.parse_status,
                               blobs.get(u.path)) for u in context.units),
        include_paths=tuple(inventory.get("declared_scope", ())),
        available_facts=tuple(sorted(context.shared_facts)),
        unclassified_entries=inventory["non_source"],
        skipped_entries=sum(inventory[k] for k in ("symlinks", "submodules", "oversize", "binary_or_non_utf8")),
        skipped_files=tuple(sorted((item["file"], item["reason"]) for item in skipped)),
        provenance="context_snapshot_checked", profile_id=context.request.profile_id,
    )
