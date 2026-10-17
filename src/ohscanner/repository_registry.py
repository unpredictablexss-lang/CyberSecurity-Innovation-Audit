"""Build a validated OpenHarmony repository registry from a repo manifest."""

from __future__ import annotations

import hashlib
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


@dataclass(frozen=True)
class Remote:
    name: str
    fetch: str

    def repository_url(self, project: str) -> str:
        return self.fetch.rstrip("/") + "/" + project + ".git"


@dataclass(frozen=True)
class RepositoryEntry:
    name: str
    path: str
    remote: str
    revision: str
    groups: Tuple[str, ...]
    url: str
    mirror_urls: Mapping[str, str]


def _safe_relative_path(value: str) -> str:
    if not value or "\\" in value or value.startswith("/") or ":" in value:
        raise ValueError("invalid manifest project path")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("invalid manifest project path")
    return value


def parse_repository_registry(manifest_path: Path) -> Dict[str, object]:
    root = ET.parse(manifest_path).getroot()
    if root.tag != "manifest":
        raise ValueError("not an OpenHarmony repo manifest")
    remotes: Dict[str, Remote] = {}
    for node in root.findall("remote"):
        name = node.get("name")
        fetch = node.get("fetch")
        if not name or not fetch or not re.fullmatch(r"https?://[^\\s]+", fetch):
            raise ValueError("invalid manifest remote")
        remotes[name] = Remote(name, fetch)
    default_node = root.find("default")
    default_remote = default_node.get("remote") if default_node is not None else None
    default_revision = default_node.get("revision") if default_node is not None else None
    entries: List[RepositoryEntry] = []
    names = set()
    paths = set()
    for node in root.findall("project"):
        name = node.get("name")
        path = node.get("path", name)
        remote_name = node.get("remote", default_remote)
        revision = node.get("revision", default_revision)
        if not name or not remote_name or not revision:
            raise ValueError("project missing name/remote/revision")
        if name in names or path in paths:
            raise ValueError("duplicate repository name/path")
        _safe_relative_path(path)
        remote = remotes.get(remote_name)
        if remote is None:
            raise ValueError("unknown project remote: " + remote_name)
        groups = tuple(sorted(item for item in node.get("groups", "").split(",") if item))
        url = remote.repository_url(name)
        mirror_urls = {
            "gitcode": "https://gitcode.com/openharmony/" + name + ".git",
            "gitee": "https://gitee.com/openharmony/" + name + ".git",
        }
        entries.append(RepositoryEntry(name, path, remote_name, revision, groups, url, mirror_urls))
        names.add(name)
        paths.add(path)
    if not entries:
        raise ValueError("manifest contains no projects")
    manifest_bytes = manifest_path.read_bytes()
    return {
        "schema_version": 1,
        "kind": "openharmony_repository_registry",
        "manifest": {
            "path": str(manifest_path),
            "sha256": hashlib.sha256(manifest_bytes).hexdigest(),
            "default_remote": default_remote,
            "default_revision": default_revision,
        },
        "policy": {
            "archive_default": "exclude",
            "archive_explicit_include": True,
            "repository_count_is_dynamic": True,
            "scan_requires_fixed_commit": True,
        },
        "repositories": [asdict(item) for item in sorted(entries, key=lambda item: item.name)],
    }


def verify_registry(registry: Mapping[str, object]) -> None:
    repositories = registry.get("repositories")
    if not isinstance(repositories, list) or not repositories:
        raise ValueError("registry has no repositories")
    names = set()
    paths = set()
    for item in repositories:
        name = item.get("name")
        path = item.get("path")
        if not isinstance(name, str) or not isinstance(path, str):
            raise ValueError("invalid repository registry entry")
        _safe_relative_path(path)
        if name in names or path in paths:
            raise ValueError("duplicate repository registry entry")
        names.add(name)
        paths.add(path)
        urls = item.get("mirror_urls")
        if not isinstance(urls, dict) or set(urls) != {"gitcode", "gitee"}:
            raise ValueError("repository mirror URLs are incomplete")
