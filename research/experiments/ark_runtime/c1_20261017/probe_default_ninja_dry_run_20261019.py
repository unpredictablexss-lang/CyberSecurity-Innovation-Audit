#!/usr/bin/env python3
"""Measure the exact GN default target with Ninja dry-run only; never executes build actions."""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "ninja_cow_target_build_20261019"
BASE = Path("/home/deepsleep/c-line-c1-profile-20261018")
OUTPUT_ROOT = BASE / "out-gn-20261019-retry3"
OUTPUT = OUTPUT_ROOT / "rk3568"
SOURCE = BASE / "openharmony-git-archive-20261019"
SOURCE_VIEW = BASE / "c1-object-source-view-20261019"
NINJA = BASE / "toolchain-20261019/ninja"
EXPECTED_NINJA_SHA256 = "2c867ca18771ff64d2a9f72f16316760651c98b1fbce692b0542f25de49b112b"
PROFILE = HERE / "product_profile_20261019.v1.json"
RESULT = EVIDENCE / "default_dry_run.v1.json"
RUN_BASE = BASE / "ninja_default_dry_run_20261019"
DRY_VIEW = RUN_BASE / "src-with-all-locked-npm-deps"
UPPER = RUN_BASE / "output-upper"
WORK = RUN_BASE / "output-work"
NPM_STAGING_REPORT = HERE / "graph_npm_staging_20261019.v1.json"
BINDINGS = [
    {
        "source_path": "developtools/ace_ets2bundle/compiler",
        "node_modules": BASE / "babel-deps-stage-20261019-retry2/node_modules",
        "provenance": BASE / "babel-deps-stage-20261019-retry2/provenance.json",
    },
    {
        "source_path": "developtools/ace_js2bundle/ace-loader",
        "node_modules": BASE / "graph-npm-stage-20261019/developtools__ace_js2bundle__ace-loader/node_modules",
        "provenance": NPM_STAGING_REPORT,
    },
    {
        "source_path": "third_party/parse5/packages/parse5",
        "node_modules": BASE / "graph-npm-stage-20261019/third_party__parse5__packages__parse5/node_modules",
        "provenance": NPM_STAGING_REPORT,
    },
    {
        "source_path": "third_party/weex-loader",
        "node_modules": BASE / "graph-npm-stage-20261019/third_party__weex-loader/node_modules",
        "provenance": NPM_STAGING_REPORT,
    },
]


def build_source_view(source_dir: Path, view_dir: Path, trie: dict[str, dict], *, root: bool = False) -> None:
    view_dir.mkdir(parents=True, exist_ok=True)
    for child in source_dir.iterdir():
        if root and child.name == "out":
            continue
        if child.name not in trie:
            target = view_dir / child.name
            if not target.exists() and not target.is_symlink():
                target.symlink_to(child, target_is_directory=child.is_dir())
            continue
        if not child.is_dir():
            raise SystemExit(f"expected source directory for npm view: {child}")
        sub_trie = trie[child.name]
        target_dir = view_dir / child.name
        if sub_trie:
            build_source_view(child, target_dir, sub_trie)
        else:
            target_dir.mkdir(parents=True, exist_ok=True)
            for package_child in child.iterdir():
                if package_child.name == "node_modules":
                    continue
                target = target_dir / package_child.name
                if not target.exists() and not target.is_symlink():
                    target.symlink_to(package_child, target_is_directory=package_child.is_dir())
            (target_dir / "node_modules").mkdir(exist_ok=True)


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    RUN_BASE.mkdir(parents=True, exist_ok=True)
    if not DRY_VIEW.exists():
        paths = [Path(binding["source_path"]).parts for binding in BINDINGS]
        trie: dict[str, dict] = {}
        for parts in paths:
            node = trie
            for part in parts:
                node = node.setdefault(part, {})
        build_source_view(SOURCE_VIEW, DRY_VIEW, trie, root=True)
        (DRY_VIEW / "out").mkdir()
    for binding in BINDINGS:
        if not binding["node_modules"].is_dir() or not binding["provenance"].is_file():
            raise SystemExit(f"locked npm dependency stage is missing: {binding['source_path']}")
    UPPER.mkdir(exist_ok=True)
    WORK.mkdir(exist_ok=True)
    build_ninja = OUTPUT / "build.ninja"
    target_source = SOURCE / "arkcompiler/ets_runtime/ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
    if sha(NINJA) != EXPECTED_NINJA_SHA256:
        raise SystemExit("hash-pinned Ninja binary mismatch")
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    before = {"build_ninja_sha256": sha(build_ninja), "target_source_sha256": sha(target_source)}
    inner = r'''set -euo pipefail
view=$1; output_root=$2; evidence=$3; upper=$4; work=$5; ninja=$6
shift 6
babel_deps=("$@")
mount --make-rprivate /
mount --bind "$view" "$view"
mount -o remount,ro,bind "$view"
mount --bind "$evidence" "$evidence"
mount -o remount,rw,bind "$evidence"
mkdir -p /src
mount --bind "$view" /src
mount -o remount,ro,bind /src
@@DEPENDENCY_MOUNTS@@
mount -t overlay overlay -o "lowerdir=$output_root,upperdir=$upper,workdir=$work,index=off,metacopy=off" /src/out
mount -o remount,ro,bind /
{
  printf 'root_mount='; findmnt -n -T / -o OPTIONS
  printf 'source_view_mount='; findmnt -n -T /src/build -o TARGET,OPTIONS
  printf 'output_overlay_mount='; findmnt -n -T /src/out/rk3568 -o TARGET,FSTYPE,OPTIONS
@@DEPENDENCY_BOUNDARIES@@
  printf 'network_namespace=%s\n' "$(readlink /proc/self/ns/net)"
  printf 'ninja_sha256=%s\n' "$(sha256sum "$ninja" | cut -d ' ' -f1)"
} > "$evidence/execution_boundary.txt"
exec "$ninja" -C /src/out/rk3568 -w dupbuild=warn -k 0 -n
'''
    mount_commands = []
    boundary_commands = []
    for index, binding in enumerate(BINDINGS):
        shell_index = f"${{babel_deps[{index}]}}"
        rel = binding["source_path"]
        mount_commands.extend([
            f"mount --bind \"{shell_index}\" \"{shell_index}\"",
            f"mount -o remount,ro,bind \"{shell_index}\"",
            f"mount --bind \"{shell_index}\" \"/src/{rel}/node_modules\"",
            f"mount -o remount,ro,bind \"/src/{rel}/node_modules\"",
        ])
        boundary_commands.append(
            f"printf 'npm_node_modules_{index}_mount='; findmnt -n -T \"/src/{rel}/node_modules\" -o TARGET,OPTIONS"
        )
    inner = inner.replace("@@DEPENDENCY_MOUNTS@@", "\n".join(mount_commands))
    inner = inner.replace("@@DEPENDENCY_BOUNDARIES@@", "\n  ".join(boundary_commands))
    command = ["unshare", "--user", "--map-root-user", "--mount", "--net", "--fork", "/bin/bash", "-c", inner,
               "--", str(DRY_VIEW), str(OUTPUT_ROOT), str(RUN_BASE), str(UPPER), str(WORK), str(NINJA),
               *[str(binding["node_modules"]) for binding in BINDINGS]]
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=0)
    assert proc.stdout is not None
    digest = hashlib.sha256()
    byte_count = line_count = command_line_count = 0
    warning_counts: Counter[str] = Counter()
    progress_totals: set[int] = set()
    first_lines: list[str] = []
    last_lines: list[str] = []
    for raw in iter(proc.stdout.readline, b""):
        digest.update(raw)
        byte_count += len(raw)
        line_count += 1
        line = raw.decode("utf-8", "replace").rstrip("\r\n")
        if line.startswith("ninja: warning:"):
            warning_counts[line.removeprefix("ninja: warning:").strip()] += 1
        elif line.startswith("ninja: error:"):
            warning_counts["ERROR: " + line.removeprefix("ninja: error:").strip()] += 1
        else:
            progress = re.match(r"^\[(\d+)/(\d+)\]", line)
            if progress:
                progress_totals.add(int(progress.group(2)))
            if line.strip():
                command_line_count += 1
        if len(first_lines) < 20:
            first_lines.append(line[:500])
        last_lines.append(line[:500])
        if len(last_lines) > 20:
            last_lines.pop(0)
    returncode = proc.wait()
    after = {"build_ninja_sha256": sha(build_ninja), "target_source_sha256": sha(target_source)}
    upper_files = sorted(path.relative_to(UPPER).as_posix() for path in UPPER.rglob("*") if path.is_file())
    boundary_path = RUN_BASE / "execution_boundary.txt"
    boundary = boundary_path.read_text(encoding="utf-8") if boundary_path.is_file() else ""
    result = {
        "schema": "ohscanner.c1.default-ninja-dry-run/v1",
        "status": "dry_run_completed" if returncode == 0 else "dry_run_graph_failure",
        "product": "hihope/rk3568",
        "profile_digest_sha256": profile.get("profile_digest_sha256"),
        "command": command,
        "ninja_sha256": sha(NINJA),
        "locked_npm_dependencies": [
            {"source_path": binding["source_path"], "staging_path": str(binding["node_modules"]),
             "provenance_sha256": sha(binding["provenance"])} for binding in BINDINGS
        ],
        "build_ninja_sha256_before": before["build_ninja_sha256"],
        "build_ninja_sha256_after": after["build_ninja_sha256"],
        "target_source_sha256_before": before["target_source_sha256"],
        "target_source_sha256_after": after["target_source_sha256"],
        "mount_boundary": boundary.splitlines(),
        "output_overlay_upper_file_count": len(upper_files),
        "output_overlay_upper_files": upper_files[:100],
        "returncode": returncode,
        "execution": "dry-run (-n); no build command is executed",
        "captured_output": {"sha256": digest.hexdigest(), "bytes": byte_count, "lines": line_count,
                            "non_diagnostic_nonempty_lines": command_line_count,
                            "progress_denominators": sorted(progress_totals),
                            "warning_counts": dict(warning_counts),
                            "first_lines": first_lines, "last_lines": last_lines},
        "keep_going": 0,
        "scope_note": "This measures the default Ninja target against the existing incremental GN output tree with unlimited keep-going and dry-run only. It is not a build result and does not establish a clean product build or snapshot completeness.",
    }
    RESULT.parent.mkdir(parents=True, exist_ok=True)
    RESULT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "returncode": returncode,
                      "captured_lines": line_count, "dry_run_command_lines": command_line_count,
                      "warning_kinds": len(warning_counts), "warnings": sum(warning_counts.values()),
                      "output_sha256": digest.hexdigest(), "result": str(RESULT)}, ensure_ascii=False, indent=2))
    return 0 if returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
