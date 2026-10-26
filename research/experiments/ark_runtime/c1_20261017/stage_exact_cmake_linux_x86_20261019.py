#!/usr/bin/env python3
"""Fetch, hash-check and safely stage the snapshot-pinned Linux x86 CMake package."""
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
DOWNLOADS = BASE / "cmake-linux-x86-stage-20261019"
ARCHIVES = DOWNLOADS / "downloads"
EXTRACT = DOWNLOADS / "contents"
DEST = BASE / "prebuilts-stage-sdk-addon-20261019/cmake/linux-x86"
REPORT = Path(__file__).with_name("cmake_linux_x86_staging_20261019.v1.json")
MIRROR = "https://repo.huaweicloud.com"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def validate(archive: tarfile.TarFile) -> list[dict[str, object]]:
    rows = []
    for member in archive.getmembers():
        path = PurePosixPath(member.name.replace("\\", "/"))
        if path.is_absolute() or any(part in ("..", "") for part in path.parts):
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
                        raise ValueError(f"archive link escapes root {member.name!r}")
                    parts.pop()
                else:
                    parts.append(part)
        if member.isdev() or member.isfifo():
            raise ValueError(f"unsupported archive member {member.name!r}")
        rows.append({"path": member.name, "kind": "symlink" if member.issym() else "hardlink" if member.islnk() else "dir" if member.isdir() else "file", "size": member.size})
    return rows


def fetch(url: str, path: Path) -> tuple[str, int]:
    req = urllib.request.Request(url, headers={"User-Agent": "C1-pinned-prebuilt-audit/1.0"})
    with urllib.request.urlopen(req, timeout=180) as response, path.open("wb") as out:
        shutil.copyfileobj(response, out)
        final_url = response.geturl()
    return final_url, path.stat().st_size


def main() -> int:
    config_bytes = CONFIG.read_bytes()
    config = json.loads(config_bytes)
    tool = next(row for row in config["tool_list"] if row.get("name") == "cmake")
    item = next(row for row in tool["config"]["linux"]["x86_64"] if row.get("unzip_filename") == "linux-x86")
    remote = item["remote_url"]
    expected_remote = "/openharmony/compiler/cmake/3.28.2/cmake-linux-x86-3.28.2.tar.gz"
    if remote != expected_remote:
        raise ValueError(f"unexpected snapshot URL: {remote}")
    url = MIRROR + remote
    ARCHIVES.mkdir(parents=True, exist_ok=True)
    EXTRACT.mkdir(parents=True, exist_ok=True)
    archive_path = ARCHIVES / Path(url).name
    sidecar_path = Path(str(archive_path) + ".sha256")
    final_url, archive_bytes = fetch(url, archive_path)
    final_sidecar, sidecar_bytes = fetch(url + ".sha256", sidecar_path)
    sidecar = sidecar_path.read_text(encoding="ascii").strip()
    match = re.fullmatch(r"([0-9a-fA-F]{64})(?:\s+.*)?", sidecar)
    if not match:
        raise ValueError(f"invalid sidecar {sidecar!r}")
    expected = match.group(1).lower()
    actual = sha256(archive_path)
    if actual != expected:
        raise ValueError(f"SHA-256 mismatch: expected {expected}, got {actual}")
    if any(EXTRACT.iterdir()):
        raise FileExistsError(f"refusing non-empty extraction directory {EXTRACT}")
    with tarfile.open(archive_path, "r:gz") as tar:
        members = validate(tar)
        tar.extractall(EXTRACT, filter="data")
    candidates = [path.parent for path in EXTRACT.rglob("cmake") if path.is_file() and path.name == "cmake" and path.parent.name == "bin"]
    if len(candidates) != 1:
        raise ValueError(f"expected one cmake binary, got {len(candidates)}")
    root = candidates[0].parent
    if DEST.exists() or DEST.is_symlink():
        raise FileExistsError(f"refusing to overwrite {DEST}")
    DEST.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(root, DEST, symlinks=True)
    if not (DEST / "BUILD.gn").is_file() or not (DEST / "bin/cmake").is_file():
        raise ValueError("staged host CMake package lacks BUILD.gn or bin/cmake")
    rows = []
    for path in sorted(DEST.rglob("*"), key=lambda p: p.relative_to(DEST).as_posix()):
        rel = path.relative_to(DEST).as_posix()
        if path.is_symlink():
            rows.append(f"L\0{rel}\0{os.readlink(path)}\n")
        elif path.is_dir():
            rows.append(f"D\0{rel}\n")
        elif path.is_file():
            rows.append(f"F\0{rel}\0{sha256(path)}\n")
    inventory_hash = hashlib.sha256("".join(rows).encode()).hexdigest()
    report = {
        "schema": "ohscanner.c1.cmake-prebuilt-staging/v1",
        "status": "snapshot_configured_archive_hash_verified_safely_staged",
        "snapshot_config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "host_platform": "linux",
        "host_cpu": "x86_64",
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
        "cmake_binary_sha256": sha256(DEST / "bin/cmake"),
        "tree_inventory_sha256": inventory_hash,
        "lifecycle_scripts_executed": False,
        "scope_note": "The archive URL is fixed by the snapshot config. The sidecar is served by the same mirror and is not an independent signature; extraction is external to the source archive and no package scripts were run."
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
