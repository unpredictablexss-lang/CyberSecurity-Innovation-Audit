#!/usr/bin/env python3
"""Fetch and safely stage the snapshot-pinned CMake ARM64 prebuilt archive."""
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
TOOL_CONFIG = SOURCE / "build/prebuilts_config.py"
DOWNLOADS = BASE / "cmake-prebuilt-stage-20261019"
ARCHIVE_DIR = DOWNLOADS / "downloads"
EXTRACT_DIR = DOWNLOADS / "contents"
INSTALL_ROOT = BASE / "prebuilts-stage-sdk-addon-20261019/cmake/linux-aarch64"
REPORT = Path(__file__).with_name("cmake_prebuilt_staging_20261019.v1.json")
MIRROR = "https://repo.huaweicloud.com"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def fetch(url: str, destination: Path) -> tuple[str, int]:
    request = urllib.request.Request(url, headers={"User-Agent": "C1-pinned-prebuilt-audit/1.0"})
    with urllib.request.urlopen(request, timeout=120) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)
        return response.geturl(), destination.stat().st_size


def validate_members(archive: tarfile.TarFile) -> list[dict[str, object]]:
    rows = []
    for member in archive.getmembers():
        name = member.name.replace("\\", "/")
        path = PurePosixPath(name)
        if path.is_absolute() or any(part in {"..", ""} for part in path.parts):
            raise ValueError(f"unsafe archive member path: {member.name!r}")
        if member.isdev() or member.isfifo():
            raise ValueError(f"unsupported special archive member: {member.name!r}")
        link_target = member.linkname if member.issym() or member.islnk() else None
        if link_target is not None:
            target = PurePosixPath(link_target.replace("\\", "/"))
            if target.is_absolute():
                raise ValueError(f"absolute archive link: {member.name!r} -> {link_target!r}")
            base = PurePosixPath() if member.islnk() else path.parent
            parts: list[str] = []
            for part in (*base.parts, *target.parts):
                if part in {"", "."}:
                    continue
                if part == "..":
                    if not parts:
                        raise ValueError(f"archive link escapes extraction root: {member.name!r}")
                    parts.pop()
                else:
                    parts.append(part)
        rows.append({"path": member.name, "kind": "symlink" if member.issym() else "hardlink" if member.islnk() else "dir" if member.isdir() else "file", "size": member.size, "link_target": link_target})
    return rows


def inventory(root: Path) -> tuple[str, int, int, int]:
    digest = hashlib.sha256()
    files = dirs = links = 0
    for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
        rel = path.relative_to(root).as_posix()
        if path.is_symlink():
            links += 1
            record = f"L\0{rel}\0{os.readlink(path)}\n".encode()
        elif path.is_dir():
            dirs += 1
            record = f"D\0{rel}\n".encode()
        elif path.is_file():
            files += 1
            record = f"F\0{rel}\0{sha256(path)}\n".encode()
        else:
            raise ValueError(f"unsupported staged item: {path}")
        digest.update(record)
    return digest.hexdigest(), files, dirs, links


def main() -> int:
    tool_config = json.loads(CONFIG.read_text(encoding="utf-8"))
    cmake = next(item for item in tool_config["tool_list"] if item["name"] == "cmake")
    item = cmake["config"]["linux"]["arm64"][0]
    relative_url = item["remote_url"]
    if relative_url != "/openharmony/compiler/cmake/3.28.2/cmake-linux-aarch64-3.28.2-20241210.tar.gz":
        raise ValueError(f"unexpected snapshot-pinned CMake URL: {relative_url}")
    url = MIRROR + relative_url
    sidecar_url = url + ".sha256"
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    archive_path = ARCHIVE_DIR / Path(url).name
    sidecar_path = ARCHIVE_DIR / (Path(url).name + ".sha256")
    archive_final_url, archive_bytes = fetch(url, archive_path)
    sidecar_final_url, sidecar_bytes = fetch(sidecar_url, sidecar_path)
    sidecar_text = sidecar_path.read_text(encoding="ascii").strip()
    match = re.fullmatch(r"([0-9a-fA-F]{64})(?:\s+.*)?", sidecar_text)
    if not match:
        raise ValueError(f"unrecognized SHA256 sidecar format: {sidecar_text!r}")
    expected = match.group(1).lower()
    observed = sha256(archive_path)
    if observed != expected:
        raise ValueError(f"archive SHA256 mismatch: expected {expected}, observed {observed}")
    if any(EXTRACT_DIR.iterdir()):
        raise FileExistsError(f"refusing to overwrite non-empty extraction directory: {EXTRACT_DIR}")
    with tarfile.open(archive_path, "r:gz") as archive:
        members = validate_members(archive)
        archive.extractall(EXTRACT_DIR, members=archive.getmembers(), filter="data")
    candidates = [path.parent for path in EXTRACT_DIR.rglob("cmake") if path.is_file() and path.name == "cmake" and path.parent.name == "bin"]
    if len(candidates) != 1:
        raise ValueError(f"expected one CMake bin directory, found {len(candidates)}")
    package_root = candidates[0].parent
    if (INSTALL_ROOT.parent).exists():
        raise FileExistsError(f"refusing to overwrite staging parent: {INSTALL_ROOT.parent}")
    INSTALL_ROOT.parent.mkdir(parents=True)
    shutil.copytree(package_root, INSTALL_ROOT, symlinks=True)
    binary = INSTALL_ROOT / "bin/cmake"
    if not binary.is_file() or not os.access(binary, os.X_OK):
        raise ValueError("staged CMake executable is missing or not executable")
    tree_hash, files, dirs, links = inventory(INSTALL_ROOT)
    report = {
        "schema": "ohscanner.c1.cmake-prebuilt-staging/v1",
        "status": "snapshot_configured_archive_hash_verified_safely_staged",
        "source_config": "build/prebuilts_config.json",
        "source_config_sha256": sha256(CONFIG),
        "tool_config_path": "build/prebuilts_config.py",
        "tool_config_sha256": sha256(TOOL_CONFIG),
        "source_package": {
            "name": "cmake",
            "host_platform": "linux",
            "host_cpu": "arm64",
            "unzip_filename": item["unzip_filename"],
            "remote_url": relative_url,
            "url": url,
            "final_url": archive_final_url,
            "archive_bytes": archive_bytes,
            "sha256_sidecar_url": sidecar_url,
            "sidecar_final_url": sidecar_final_url,
            "sidecar_bytes": sidecar_bytes,
            "sidecar_value": expected,
            "archive_sha256": observed,
            "archive_member_count": len(members),
            "archive_paths_and_links_validated": True
        },
        "staging_path": str(INSTALL_ROOT),
        "cmake_binary_sha256": sha256(binary),
        "tree_inventory_sha256": tree_hash,
        "tree_files": files,
        "tree_directories": dirs,
        "tree_symlinks": links,
        "lifecycle_scripts_executed": False,
        "scope_note": "Static snapshot-configured tool artifact staged outside the source archive. Downloaded sidecar and archive come from the same Huawei Cloud mirror; the bytes are captured by SHA256 but no independent signature is claimed."
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "archive_sha256": observed, "cmake_sha256": report["cmake_binary_sha256"], "tree_inventory_sha256": tree_hash, "report": str(REPORT)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
