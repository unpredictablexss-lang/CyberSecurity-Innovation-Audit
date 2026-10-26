#!/usr/bin/env python3
"""Install only lockfile-bound Ninja npm inputs into isolated external staging."""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
BASE = Path("/home/deepsleep/c-line-c1-profile-20261018")
SOURCE = BASE / "openharmony-git-archive-20261019"
REPOS = Path("/mnt/d/OpenHarmony807/repos")
NODE = BASE / "prebuilts-stage-20261019/build-tools/common/nodejs/node-v14.21.1-linux-x64"
NODE_SHA256 = "6f920cf526ac67c66756848a9622d29d8596b136fec7b93cfe43f8290fc2d223"
AUDIT = HERE / "declared_npm_projects_20261019.v1.json"
STAGE_ROOT = BASE / "graph-npm-stage-20261019"
SHARED_CACHE = BASE / "graph-npm-cache-20261019"
INVENTORY_ROOT = HERE / "npm_node_modules_inventory_20261019"
RESULT = HERE / "graph_npm_staging_20261019.v1.json"
REGISTRY = "https://repo.huaweicloud.com/repository/npm/"

EXPECTED = {
    "developtools/ace_js2bundle/ace-loader": {
        "commit": "9da4e6b49ce9b6d7429193dd4734acab6de9feb6",
        "tree": "a72ffc3c9685094e4fd4bf675f1c5fa45b557524",
        "package_json_git_blob": "b5772631fb7c0a260c3b69be211e65a7f8284474",
        "package-lock_json_git_blob": "723b5df67179ad90d06fc5581229cd2035248ec7",
        "package_json_sha256": "ba2d853c268e115d4ca1f8331c3d2473fe30d9e7268ee26ad1ae09c771d0934a",
        "package-lock_json_sha256": "5f68037cbc095063f56bf5915464b0bb9f1bc1ae9f0da710f77571fd2e5d5b36",
        "locked_packages": 598,
    },
    "third_party/parse5/packages/parse5": {
        "commit": "e2741d61789d82093c07ea5e74035a155944f290",
        "tree": "86df48e0c2adfd018559028407238abdf8041366",
        "package_json_git_blob": "c021d5fcb2f7fe366bae0d66618e227bece1dbab",
        "package-lock_json_git_blob": "dcbe9d80e5782e767eb0481cf7a14fe2b6f1dc9d",
        "package_json_sha256": "23f04a828fe7cfd95b77bd4cc1bd6392b7fcec73798b658380cba5c2e01532cb",
        "package-lock_json_sha256": "04da4b00d4ee63724da451b57719e751ecdc9ed5074f6a448fdd53168a605165",
        "locked_packages": 3,
    },
    "third_party/weex-loader": {
        "commit": "7e94bb435896bd29edd098d7bc845bfc4cf098de",
        "tree": "d5ae6137bfa4065f44d9976b3730abbb957bf968",
        "package_json_git_blob": "10d06efa1420f2507aca8b5330218ddbb784ba43",
        "package-lock_json_git_blob": "adf6c1e873116d44367f75d6edaabb436f939a21",
        "package_json_sha256": "c35f0041f9f4c1a9b7df28807889d4b79f65974b81afb0ca59c7e1bd7bb935ba",
        "package-lock_json_sha256": "f8eaf8f113a68d5dd53557af45abd3304e2180f89bc1481c328cb72963aa5751",
        "locked_packages": 205,
    },
}


def sha_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def git(repo: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(repo), *args], text=True).strip()


def lock_audit(lock: dict) -> dict:
    counts = {"packages": 0, "missing_integrity": 0, "non_mirror_url": 0, "git_or_file_url": 0}

    def visit(dependencies: dict) -> None:
        for item in dependencies.values():
            counts["packages"] += 1
            url = item.get("resolved", "")
            counts["missing_integrity"] += not bool(item.get("integrity"))
            counts["non_mirror_url"] += not url.startswith(REGISTRY)
            counts["git_or_file_url"] += url.startswith(("git+", "git://", "file:"))
            visit(item.get("dependencies", {}))

    visit(lock.get("dependencies", {}))
    return counts


def inventory_tree(root: Path, destination: Path) -> dict:
    rows = []
    for path in sorted(root.rglob("*"), key=lambda p: p.relative_to(root).as_posix()):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            rows.append({"path": relative, "type": "symlink", "target": str(path.readlink())})
        elif path.is_file():
            rows.append({"path": relative, "type": "file", "bytes": path.stat().st_size, "sha256": sha(path)})
        elif path.is_dir():
            rows.append({"path": relative, "type": "directory"})
    payload = {
        "schema": "ohscanner.c1.node-modules-inventory/v1",
        "status": "content_hashed",
        "file_count": sum(row["type"] == "file" for row in rows),
        "directory_count": sum(row["type"] == "directory" for row in rows),
        "symlink_count": sum(row["type"] == "symlink" for row in rows),
        "entries": rows,
    }
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    return {"path": destination.relative_to(HERE).as_posix(), "sha256": sha(destination), **{k: payload[k] for k in ("file_count", "directory_count", "symlink_count")}}


def install_one(source_rel: str, expected: dict) -> dict:
    source = SOURCE / source_rel
    material = json.loads(AUDIT.read_text(encoding="utf-8"))
    row = next(x for x in material["projects"] if x.get("source_path") == source_rel)
    pin_path = row["manifest_project"]
    repo = REPOS / pin_path.replace("/", "_")
    commit = row["manifest_commit"]
    project_relative = source_rel[len(pin_path) :].strip("/")
    if not project_relative:
        project_relative = "."
    tree = git(repo, "rev-parse", f"{commit}^{{tree}}")
    observed = {"commit": commit, "tree": tree}
    for file_name in ("package.json", "package-lock.json"):
        path = source / file_name
        sha_key = file_name.replace(".", "_") + "_sha256"
        blob_key = file_name.replace(".", "_") + "_git_blob"
        blob_path = f"{project_relative}/{file_name}" if project_relative != "." else file_name
        observed[sha_key] = sha(path)
        observed[blob_key] = git(repo, "rev-parse", f"{commit}:{blob_path}")
        blob = subprocess.check_output(["git", "-C", str(repo), "cat-file", "blob", observed[blob_key]])
        if sha_bytes(blob) != observed[sha_key]:
            raise SystemExit(f"source bytes differ from pinned Git blob for {source_rel}/{file_name}")
    for key, value in expected.items():
        if key == "locked_packages":
            continue
        if observed.get(key) != value:
            raise SystemExit(f"identity mismatch for {source_rel} {key}: {observed.get(key)} != {value}")
    lock = json.loads((source / "package-lock.json").read_text(encoding="utf-8"))
    audit = lock_audit(lock)
    if audit != {"packages": expected["locked_packages"], "missing_integrity": 0, "non_mirror_url": 0, "git_or_file_url": 0}:
        raise SystemExit(f"lock audit mismatch for {source_rel}: {audit}")
    stage = STAGE_ROOT / source_rel.replace("/", "__")
    log = stage / "npm-ci.log"
    reused = stage.exists()
    if reused:
        if sha(stage / "package.json") != expected["package_json_sha256"] or sha(stage / "package-lock.json") != expected["package-lock_json_sha256"]:
            raise SystemExit(f"existing stage manifests do not match pinned source: {stage}")
        if not log.is_file() or not (stage / "node_modules").is_dir():
            raise SystemExit(f"existing stage is incomplete and will not be overwritten: {stage}")
        stdout = log.read_text(encoding="utf-8", errors="replace")
        returncode = 0 if f"added {expected['locked_packages']} packages" in stdout else 1
    else:
        stage.mkdir(parents=True)
        shutil.copyfile(source / "package.json", stage / "package.json")
        shutil.copyfile(source / "package-lock.json", stage / "package-lock.json")
    inner = r'''set -euo pipefail
stage=$1; node=$2; project=$3; cache=$4; registry=$5
mount --make-rprivate /
mount --bind "$stage" "$stage"
mount -o remount,rw,bind "$stage"
mount --bind "$project" "$project"
mount -o remount,ro,bind "$project"
mount --bind "$node" "$node"
mount -o remount,ro,bind "$node"
mount --bind "$cache" "$cache"
mount -o remount,rw,bind "$cache"
mkdir -p "$stage/home" "$stage/tmp"
export HOME="$stage/home" TMPDIR="$stage/tmp" PATH="$node/bin:$PATH"
export npm_config_cache="$cache" npm_config_ignore_scripts=true npm_config_audit=false npm_config_fund=false npm_config_update_notifier=false npm_config_userconfig=/dev/null
cd "$stage"
printf 'project='; findmnt -n -T "$project" -o TARGET,OPTIONS
printf 'node='; findmnt -n -T "$node" -o TARGET,OPTIONS
printf 'stage='; findmnt -n -T "$stage" -o TARGET,OPTIONS
printf 'cache='; findmnt -n -T "$cache" -o TARGET,OPTIONS
printf 'node_version='; "$node/bin/node" --version
printf 'npm_version='; "$node/bin/npm" --version
exec "$node/bin/npm" ci --ignore-scripts --no-audit --no-fund --registry "$registry" --cache "$cache"
'''
    command = ["unshare", "--user", "--map-root-user", "--mount", "--fork", "/bin/bash", "-c", inner,
               "--", str(stage), str(NODE), str(source), str(SHARED_CACHE), REGISTRY]
    if not reused:
        process = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        stdout = process.stdout
        returncode = process.returncode
        log.write_text(stdout, encoding="utf-8")
    node_modules = stage / "node_modules"
    if returncode != 0 or not (node_modules / "@babel/cli/bin/babel.js").is_file() and "babel" in source_rel:
        raise SystemExit(f"npm ci failed or expected input absent for {source_rel}: rc={returncode}; see {log}")
    inventory_path = INVENTORY_ROOT / (source_rel.replace("/", "__") + ".json")
    if inventory_path.is_file():
        inventory_payload = json.loads(inventory_path.read_text(encoding="utf-8"))
        inventory = {"path": inventory_path.relative_to(HERE).as_posix(), "sha256": sha(inventory_path),
                     **{k: inventory_payload[k] for k in ("file_count", "directory_count", "symlink_count")}}
    else:
        inventory = inventory_tree(node_modules, inventory_path)
    return {
        "source_path": source_rel,
        "manifest_project": pin_path,
        "commit": commit,
        "tree": tree,
        "package_json_sha256": observed["package_json_sha256"],
        "package_json_git_blob": observed["package_json_git_blob"],
        "package_lock_sha256": observed["package-lock_json_sha256"],
        "package_lock_git_blob": observed["package-lock_json_git_blob"],
        "lock_audit": audit,
        "npm_ci_command": command,
        "returncode": returncode,
        "reused_completed_install": reused,
        "lifecycle_scripts_enabled": False,
        "log_sha256": sha(log),
        "staging_path": str(node_modules),
        "inventory": inventory,
        "mount_evidence": stdout.splitlines()[:8],
    }


def main() -> int:
    if sha(NODE / "bin/node") != NODE_SHA256:
        raise SystemExit("pinned Node binary hash mismatch")
    if sha(AUDIT) == "":
        raise SystemExit("missing npm project audit")
    STAGE_ROOT.mkdir(parents=True, exist_ok=True)
    SHARED_CACHE.mkdir(parents=True, exist_ok=True)
    results = [install_one(source_rel, expected) for source_rel, expected in EXPECTED.items()]
    report = {
        "schema": "ohscanner.c1.graph-npm-staging/v1",
        "status": "all_locked_npm_inputs_staged",
        "node_version": "v14.21.1",
        "node_sha256": NODE_SHA256,
        "registry": REGISTRY,
        "network_namespace_isolated": False,
        "source_and_runtime_mounts_read_only": True,
        "lifecycle_scripts_enabled": False,
        "packages": results,
        "scope_note": "Only package manifests from exact manifest-pinned snapshots were installed. All tarballs were resolved through lockfile URLs and integrity values; npm lifecycle scripts were disabled. The outputs are external staging and are mounted read-only for a later no-network Ninja dry-run.",
    }
    RESULT.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "packages": [
        {"source_path": x["source_path"], "returncode": x["returncode"], "inventory": x["inventory"], "log_sha256": x["log_sha256"]}
        for x in results]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
