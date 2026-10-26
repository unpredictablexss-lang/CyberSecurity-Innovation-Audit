#!/usr/bin/env python3
"""Fetch and safely stage snapshot-pinned Linux x86 Ninja."""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath

BASE = Path("/home/deepsleep/c-line-c1-profile-20261018")
SOURCE = BASE / "openharmony-git-archive-20261019"
CONFIG = SOURCE / "build/prebuilts_config.json"
DOWNLOADS = BASE / "ninja-prebuilt-stage-20261019"
ARCHIVES = DOWNLOADS / "downloads"
EXTRACT = DOWNLOADS / "contents"
DEST = BASE / "prebuilts-stage-sdk-addon-20261019/build-tools/linux-x86/bin"
REPORT = Path(__file__).with_name("ninja_prebuilt_staging_20261019.v1.json")
MIRROR = "https://repo.huaweicloud.com"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(url: str, path: Path) -> tuple[str, int]:
    req = urllib.request.Request(url, headers={"User-Agent": "C1-pinned-prebuilt-audit/1.0"})
    with urllib.request.urlopen(req, timeout=180) as response, path.open("wb") as out:
        shutil.copyfileobj(response, out)
        final = response.geturl()
    return final, path.stat().st_size


def validate(tar: tarfile.TarFile) -> list[dict[str, object]]:
    rows = []
    for member in tar.getmembers():
        path = PurePosixPath(member.name.replace("\\", "/"))
        if path.is_absolute() or any(part in ("", "..") for part in path.parts):
            raise ValueError(f"unsafe archive path {member.name!r}")
        if member.issym() or member.islnk():
            target = PurePosixPath(member.linkname.replace("\\", "/"))
            if target.is_absolute():
                raise ValueError(f"absolute archive link {member.name!r}")
            parts: list[str] = []
            base = PurePosixPath() if member.islnk() else path.parent
            for part in (*base.parts, *target.parts):
                if part in ("", "."):
                    continue
                if part == "..":
                    if not parts:
                        raise ValueError(f"archive link escapes extraction root {member.name!r}")
                    parts.pop()
                else:
                    parts.append(part)
        if member.isdev() or member.isfifo():
            raise ValueError(f"unsupported archive member {member.name!r}")
        rows.append({"path": member.name, "kind": "symlink" if member.issym() else "hardlink" if member.islnk() else "dir" if member.isdir() else "file", "size": member.size})
    return rows


def main() -> int:
    config_bytes = CONFIG.read_bytes()
    config = json.loads(config_bytes)
    tool = next(row for row in config["tool_list"] if row.get("name") == "ninja")
    item = next(row for row in tool["config"]["linux"]["x86_64"] if row["remote_url"].endswith("ninja-linux-x86-1.13.2-20260810.tar.gz"))
    remote = item["remote_url"]
    url = MIRROR + remote
    ARCHIVES.mkdir(parents=True, exist_ok=True)
    EXTRACT.mkdir(parents=True, exist_ok=True)
    archive = ARCHIVES / Path(url).name
    sidecar_path = Path(str(archive) + ".sha256")
    final_url, archive_bytes = fetch(url, archive)
    final_sidecar, sidecar_bytes = fetch(url + ".sha256", sidecar_path)
    sidecar = sidecar_path.read_text(encoding="ascii").strip()
    match = re.fullmatch(r"([0-9a-fA-F]{64})(?:\s+.*)?", sidecar)
    if not match:
        raise ValueError(f"invalid sha256 sidecar: {sidecar!r}")
    expected = match.group(1).lower()
    actual = sha256(archive)
    if actual != expected:
        raise ValueError(f"archive hash mismatch: expected {expected}, got {actual}")
    if any(EXTRACT.iterdir()):
        raise FileExistsError(f"refusing non-empty extraction directory {EXTRACT}")
    with tarfile.open(archive, "r:gz") as tar:
        members = validate(tar)
        tar.extractall(EXTRACT, filter="data")
    binaries = [p for p in EXTRACT.rglob("ninja") if p.is_file() and p.name == "ninja"]
    build_files = [p for p in EXTRACT.rglob("BUILD.gn") if p.is_file()]
    if len(binaries) != 1 or len(build_files) != 1:
        raise ValueError(f"expected one ninja executable and BUILD.gn, found {len(binaries)} and {len(build_files)}")
    if DEST.exists():
        raise FileExistsError(f"refusing to overwrite {DEST}")
    DEST.mkdir(parents=True, exist_ok=True)
    shutil.copy2(binaries[0], DEST / "ninja")
    shutil.copy2(build_files[0], DEST / "BUILD.gn")
    (DEST / "ninja").chmod(0o755)
    report = {
        "schema": "ohscanner.c1.snapshot-prebuilt-staging/v1",
        "status": "snapshot_configured_archive_hash_verified_safely_staged",
        "tool": "ninja",
        "snapshot_config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "remote_path": remote,
        "archive_url": final_url,
        "sidecar_url": final_sidecar,
        "sidecar_sha256": expected,
        "archive_sha256": actual,
        "archive_bytes": archive_bytes,
        "sidecar_bytes": sidecar_bytes,
        "archive_member_count": len(members),
        "archive_paths_and_links_validated": True,
        "staging_path": str(DEST),
        "staged_files": {"ninja": sha256(DEST / "ninja"), "BUILD.gn": sha256(DEST / "BUILD.gn")},
        "lifecycle_scripts_executed": False,
        "scope_note": "The URL is from the exact snapshot config. The publisher sidecar is served by the same mirror and is not an independent signature. Only the executable and its package BUILD.gn were staged outside the source archive."
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
