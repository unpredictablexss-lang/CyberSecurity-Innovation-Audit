from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Mapping, Protocol


_OID = re.compile(r"^[a-f0-9]{40}$")


class GitObjectLookup(Protocol):
    repository: str

    def object_type(self, object_id: str) -> str: ...
    def blob_bytes(self, object_id: str) -> bytes: ...
    def path_blob(self, commit_id: str, path: str) -> str: ...


@dataclass(frozen=True)
class SourceIdentity:
    repository: str
    commit: str
    tree: str
    blob: str
    source_sha256: str
    path: str
    status: str
    reason: str


def _require_oid(value: object, field: str) -> str:
    if not isinstance(value, str) or not _OID.fullmatch(value):
        raise ValueError(field + " must be a full 40-character Git object ID")
    return value


def resolve_source_identity(claim: Mapping[str, object], lookup: GitObjectLookup) -> SourceIdentity:
    """Resolve a source identity only after repository and Git object binding succeeds.

    Short HEAD values, URLs, paths, and commit-message claims are never accepted.
    A failed or partial lookup is returned as explicit-unknown and never upgraded.
    """
    repository = claim.get("repository")
    path = claim.get("path")
    if not isinstance(repository, str) or not repository.strip():
        raise ValueError("source identity needs repository")
    if not isinstance(path, str) or not path.replace("\\", "/").strip():
        raise ValueError("source identity needs path")
    normalized_path = path.replace("\\", "/")
    try:
        commit = _require_oid(claim.get("commit"), "commit")
        tree = _require_oid(claim.get("tree"), "tree")
        blob = _require_oid(claim.get("blob"), "blob")
        source_sha256 = claim.get("source_sha256")
        if not isinstance(source_sha256, str) or not re.fullmatch(r"[a-f0-9]{64}", source_sha256):
            raise ValueError("source_sha256 must be a full SHA-256")
        if lookup.repository != repository:
            raise ValueError("repository binding mismatch")
        if lookup.object_type(commit) != "commit":
            raise ValueError("commit object type mismatch")
        if lookup.object_type(tree) != "tree":
            raise ValueError("tree object type mismatch")
        if lookup.object_type(blob) != "blob":
            raise ValueError("blob object type mismatch")
        if lookup.path_blob(commit, normalized_path) != blob:
            raise ValueError("commit/tree/path/blob binding mismatch")
        data = lookup.blob_bytes(blob)
        if hashlib.sha256(data).hexdigest() != source_sha256:
            raise ValueError("source SHA-256 mismatch")
    except (KeyError, ValueError, OSError) as exc:
        return SourceIdentity(
            repository=repository,
            commit=str(claim.get("commit", "")),
            tree=str(claim.get("tree", "")),
            blob=str(claim.get("blob", "")),
            source_sha256=str(claim.get("source_sha256", "")),
            path=normalized_path,
            status="explicit-unknown",
            reason="source unavailable/unknown: " + str(exc),
        )
    return SourceIdentity(
        repository=repository,
        commit=commit,
        tree=tree,
        blob=blob,
        source_sha256=source_sha256,
        path=normalized_path,
        status="verified",
        reason="repository, full commit/tree/blob/path binding, and source SHA-256 verified",
    )
