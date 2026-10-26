#!/usr/bin/env python3
"""Materialize the pinned Ace ETS compiler npm lock in isolated external staging."""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

BASE = Path("/home/deepsleep/c-line-c1-profile-20261018")
ARCHIVE = BASE / "openharmony-git-archive-20261019"
REPO = Path("/mnt/d/OpenHarmony807/repos/developtools_ace_ets2bundle")
PROJECT = ARCHIVE / "developtools/ace_ets2bundle/compiler"
STAGE = BASE / "babel-deps-stage-20261019-retry2"
NODE = BASE / "prebuilts-stage-20261019/build-tools/common/nodejs/node-v14.21.1-linux-x64"
EXPECTED_COMMIT = "9e0f9e58a243d7aeab672c317a2322dc37efd1a7"
EXPECTED_TREE = "980cb7563f3e3c17c0f2a1147a6a7c1a71cbbf25"
EXPECTED_LOCK_BLOB = "3eaad929521571dfd04c648b3b669b4594ae16b8"
EXPECTED_PACKAGE_BLOB = "6961cb6a785d83245fe0440eed8f0cb3bd7730c6"
EXPECTED_LOCK_SHA256 = "53da389f9a63312ade250a843c875158679bd259d41577793914786dcec268b4"
EXPECTED_PACKAGE_SHA256 = "6d901fa8d550ddafad82bfc50c32bf0984c417eb358e89169fb4285d003f65e4"
REGISTRY = "https://repo.huaweicloud.com/repository/npm/"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def main() -> int:
    commit = git(REPO, "rev-parse", "HEAD")
    tree = git(REPO, "rev-parse", "HEAD^{tree}")
    lock_blob = git(REPO, "rev-parse", "HEAD:compiler/package-lock.json")
    package_blob = git(REPO, "rev-parse", "HEAD:compiler/package.json")
    expected = (EXPECTED_COMMIT, EXPECTED_TREE, EXPECTED_LOCK_BLOB, EXPECTED_PACKAGE_BLOB)
    observed = (commit, tree, lock_blob, package_blob)
    if observed != expected:
        raise SystemExit(f"pinned project identity mismatch: {observed!r}")
    lock_path = PROJECT / "package-lock.json"
    package_path = PROJECT / "package.json"
    if sha256(lock_path) != EXPECTED_LOCK_SHA256 or sha256(package_path) != EXPECTED_PACKAGE_SHA256:
        raise SystemExit("snapshot package manifests do not match pinned hashes")
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    records = 0
    missing_integrity: list[str] = []
    unexpected_url: list[str] = []

    def visit(dependencies: dict, prefix: str = "") -> None:
        nonlocal records
        for name, item in dependencies.items():
            records += 1
            resolved = item.get("resolved", "")
            if not item.get("integrity"):
                missing_integrity.append(prefix + name)
            if not resolved.startswith(REGISTRY):
                unexpected_url.append(prefix + name + "=" + resolved)
            visit(item.get("dependencies", {}), prefix + name + "/")

    visit(lock.get("dependencies", {}))
    if records != 523 or missing_integrity or unexpected_url:
        raise SystemExit(f"lock audit failed: records={records}, no_integrity={missing_integrity[:5]}, urls={unexpected_url[:5]}")
    if STAGE.exists():
        raise SystemExit(f"refusing to reuse existing staging directory: {STAGE}")
    STAGE.mkdir(parents=True)
    shutil.copyfile(package_path, STAGE / "package.json")
    shutil.copyfile(lock_path, STAGE / "package-lock.json")
    install_log = STAGE / "npm-ci.log"
    inner = r'''set -euo pipefail
stage=$1; node=$2; project=$3; registry=$4
mount --make-rprivate /
mount --bind "$stage" "$stage"
mount -o remount,rw,bind "$stage"
mount --bind "$project" "$project"
mount -o remount,ro,bind "$project"
mount --bind "$node" "$node"
mount -o remount,ro,bind "$node"
mkdir -p "$stage/home" "$stage/cache" "$stage/tmp"
export HOME="$stage/home" TMPDIR="$stage/tmp"
export PATH="$node/bin:$PATH"
export npm_config_cache="$stage/cache"
export npm_config_ignore_scripts=true npm_config_audit=false npm_config_fund=false npm_config_update_notifier=false
export npm_config_userconfig=/dev/null
cd "$stage"
printf 'root='; findmnt -n -T / -o OPTIONS
printf 'stage='; findmnt -n -T "$stage" -o TARGET,OPTIONS
printf 'project='; findmnt -n -T "$project" -o TARGET,OPTIONS
printf 'node='; findmnt -n -T "$node" -o TARGET,OPTIONS
printf 'network_namespace=%s\n' "$(readlink /proc/self/ns/net)"
printf 'node_version='; "$node/bin/node" --version
printf 'npm_version='; "$node/bin/npm" --version
exec "$node/bin/npm" ci --ignore-scripts --no-audit --no-fund --registry "$registry" --cache "$stage/cache"
'''
    command = [
        "unshare", "--user", "--map-root-user", "--mount", "--fork", "/bin/bash", "-c", inner,
        "--", str(STAGE), str(NODE), str(PROJECT), REGISTRY,
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    install_log.write_text(result.stdout, encoding="utf-8")
    babel_cli = STAGE / "node_modules/@babel/cli/bin/babel.js"
    report = {
        "schema": "ohscanner.c1.babel-dependency-stage/v1",
        "status": "ready_for_read_only_dry_run" if result.returncode == 0 and babel_cli.is_file() else "install_failed_or_cli_missing",
        "source": {
            "repository": "developtools/ace_ets2bundle",
            "commit": commit,
            "tree": tree,
            "package_json_blob": package_blob,
            "package_json_sha256": sha256(package_path),
            "package_lock_blob": lock_blob,
            "package_lock_sha256": sha256(lock_path),
            "lockfile_version": lock.get("lockfileVersion"),
            "locked_package_records": records,
            "all_records_have_integrity": not missing_integrity,
            "all_resolved_urls_use_configured_registry": not unexpected_url,
            "lifecycle_scripts_enabled": False,
        },
        "execution": {
            "command": command,
            "returncode": result.returncode,
            "log_path": str(install_log),
            "log_sha256": sha256(install_log),
            "babel_cli_exists": babel_cli.is_file(),
            "staging_path": str(STAGE),
            "network_namespace_isolated": False,
            "root_filesystem_read_only": "root=ro" in result.stdout,
            "pinned_project_mount_read_only": bool(re.search(r"^project=.*\bro(?:,|$)", result.stdout, re.MULTILINE)),
            "node_runtime_mount_read_only": bool(re.search(r"^node=.*\bro(?:,|$)", result.stdout, re.MULTILINE)),
        },
    }
    (STAGE / "provenance.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "returncode": result.returncode,
                      "records": records, "babel_cli_exists": babel_cli.is_file(),
                      "log_sha256": report["execution"]["log_sha256"],
                      "last_lines": result.stdout.splitlines()[-12:]}, indent=2))
    return result.returncode if result.returncode else (0 if babel_cli.is_file() else 1)


if __name__ == "__main__":
    raise SystemExit(main())
