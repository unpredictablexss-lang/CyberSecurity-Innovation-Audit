#!/usr/bin/env python3
"""Fetch, verify and safely stage the snapshot-pinned Linux x86_64 Clang archive."""
from __future__ import annotations

import hashlib
import json
import shutil
import tarfile
import urllib.request
from pathlib import Path, PurePosixPath

BASE = Path("/home/deepsleep/c-line-c1-profile-20261018")
SOURCE = BASE / "openharmony-git-archive-20261019"
CONFIG = SOURCE / "build/prebuilts_config.json"
DOWNLOADS = BASE / "clang-prebuilt-stage-20261019"
ARCHIVE_DIR = DOWNLOADS / "downloads"
EXTRACT_DIR = DOWNLOADS / "contents"
INSTALL_ROOT = BASE / "prebuilts-stage-sdk-addon-20261019/clang/ohos/linux-x86_64/llvm"
REPORT = Path(__file__).with_name("clang_prebuilt_staging_20261019.v1.json")
MIRROR = "https://repo.huaweicloud.com"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, path: Path) -> tuple[str, int]:
    request = urllib.request.Request(url, headers={"User-Agent": "C1-pinned-prebuilt-audit/1.0"})
    with urllib.request.urlopen(request, timeout=180) as response, path.open("wb") as output:
        shutil.copyfileobj(response, output)
        final_url = response.geturl()
    return final_url, path.stat().st_size


def validate_tar(archive: tarfile.TarFile) -> list[dict[str, object]]:
    members = archive.getmembers()
    seen: set[str] = set()
    rows: list[dict[str, object]] = []
    for member in members:
        name = member.name.replace("\\", "/")
        path = PurePosixPath(name)
        if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
            raise ValueError(f"unsafe archive path: {member.name!r}")
        if name in seen:
            raise ValueError(f"duplicate archive path: {name}")
        seen.add(name)
        if member.issym() or member.islnk():
            target = PurePosixPath(member.linkname.replace("\\", "/"))
            resolved = target if target.is_absolute() else path.parent / target
            stack: list[str] = []
            for part in resolved.parts:
                if part in ("", ".", "/"):
                    continue
                if part == "..":
                    if not stack:
                        raise ValueError(f"unsafe archive link: {member.name!r} -> {member.linkname!r}")
                    stack.pop()
                else:
                    stack.append(part)
            if target.is_absolute():
                raise ValueError(f"absolute archive link: {member.name!r} -> {member.linkname!r}")
        if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
            raise ValueError(f"unsupported archive member type: {member.name!r}")
        rows.append({"name": name, "type": "file" if member.isfile() else "dir" if member.isdir() else "link", "size": member.size})
    return rows


def main() -> int:
    config_bytes = CONFIG.read_bytes()
    config = json.loads(config_bytes)
    entry = next(item for item in config["tool_list"] if item.get("name") == "clang")
    item = next(item for item in entry["config"]["linux"]["x86_64"] if "/linux/clang_linux-x86_64-02fbe8-20260908.tar.gz" in item["remote_url"])
    relative_url = item["remote_url"]
    archive_url = MIRROR + relative_url
    archive_path = ARCHIVE_DIR / Path(relative_url).name
    sidecar_path = Path(str(archive_path) + ".sha256")
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    EXTRACT_DIR.mkdir(parents=True, exist_ok=True)
    INSTALL_ROOT.parent.mkdir(parents=True, exist_ok=True)
    final_archive_url, archive_bytes = download(archive_url, archive_path)
    final_sidecar_url, sidecar_bytes = download(archive_url + ".sha256", sidecar_path)
    sidecar_text = sidecar_path.read_text(encoding="ascii").strip()
    expected = sidecar_text.split()[0].lower()
    if len(expected) != 64 or any(char not in "0123456789abcdef" for char in expected):
        raise ValueError(f"invalid sha256 sidecar: {sidecar_text!r}")
    actual = sha256(archive_path)
    if actual != expected:
        raise ValueError(f"archive SHA-256 mismatch: expected {expected}, got {actual}")

    extracted_root = EXTRACT_DIR / "clang_linux-x86_64-02fbe8-20260908"
    if extracted_root.exists():
        shutil.rmtree(extracted_root)
    with tarfile.open(archive_path, "r:gz") as archive:
        members = validate_tar(archive)
        archive.extractall(EXTRACT_DIR, filter="data")
    if not extracted_root.is_dir():
        raise ValueError(f"expected archive root absent: {extracted_root}")
    if INSTALL_ROOT.exists() or INSTALL_ROOT.is_symlink():
        if INSTALL_ROOT.is_symlink() or INSTALL_ROOT.is_file():
            INSTALL_ROOT.unlink()
        else:
            shutil.rmtree(INSTALL_ROOT)
    shutil.move(str(extracted_root), str(INSTALL_ROOT))
    required = [INSTALL_ROOT / "NOTICE", INSTALL_ROOT / "bin/clang", INSTALL_ROOT / "bin/clang++"]
    missing = [str(path.relative_to(INSTALL_ROOT)) for path in required if not path.is_file()]
    if missing:
        raise ValueError(f"required Clang paths missing: {missing}")
    inventory = []
    for path in sorted(INSTALL_ROOT.rglob("*")):
        rel = path.relative_to(INSTALL_ROOT).as_posix()
        if path.is_symlink():
            inventory.append({"path": rel, "type": "symlink", "target": path.readlink().as_posix()})
        elif path.is_file():
            inventory.append({"path": rel, "type": "file", "size": path.stat().st_size, "sha256": sha256(path)})
    inventory_bytes = json.dumps(inventory, sort_keys=True, separators=(",", ":")).encode()
    report = {
        "schema": "ohscanner.c1.snapshot-prebuilt-staging/v1",
        "status": "snapshot_configured_archive_hash_verified_safely_staged",
        "tool": "clang",
        "snapshot_config_sha256": hashlib.sha256(config_bytes).hexdigest(),
        "snapshot_config_remote_path": relative_url,
        "archive_url": final_archive_url,
        "sidecar_url": final_sidecar_url,
        "sidecar_sha256": expected,
        "archive_sha256": actual,
        "archive_bytes": archive_bytes,
        "sidecar_bytes": sidecar_bytes,
        "archive_member_count": len(members),
        "archive_paths_and_links_validated": True,
        "extracted_with_python_tarfile_data_filter": True,
        "required_paths": ["NOTICE", "bin/clang", "bin/clang++"],
        "staging_path": str(INSTALL_ROOT),
        "tree_inventory_sha256": hashlib.sha256(inventory_bytes).hexdigest(),
        "file_count": sum(row["type"] == "file" for row in inventory),
        "symlink_count": sum(row["type"] == "symlink" for row in inventory),
        "lifecycle_scripts_executed": False,
        "scope_note": "Publisher sidecar verification establishes archive equality with the mirror-published digest; it is not an independent signature. Artifact was extracted outside the repository without executing package scripts.",
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
