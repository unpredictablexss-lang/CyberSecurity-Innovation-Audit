#!/usr/bin/env python3
"""Run only the exact profiled Clang compile actions into an external scratch tree.

The driver does not invoke GN, Ninja, shell scripts, or a linker. It builds a
symlink-only source-root view so the original relative include arguments keep
their product layout; only -o and -MF destinations are redirected to evidence.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
from pathlib import Path


def sha256_file(path: Path) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            h.update(block)
    return h.hexdigest(), size


def make_source_view(source: Path, prebuilts: Path, toolchain: Path, view: Path, output: Path) -> None:
    if view.exists():
        raise SystemExit(f"refusing to reuse existing compile source view: {view}")
    view.mkdir(parents=True)
    for entry in source.iterdir():
        # The archive includes an empty `out` project root; the exact GN output
        # tree is supplied separately below, so keep that mount point writable.
        if entry.name in {"prebuilts", "out"}:
            continue
        (view / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())

    pre = view / "prebuilts"
    pre.mkdir()
    for entry in prebuilts.iterdir():
        if entry.name == "clang":
            continue
        (pre / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())
    clang = pre / "clang/ohos/linux-x86_64"
    clang.mkdir(parents=True)
    (clang / "llvm").symlink_to(
        toolchain / "clang_linux-x86_64-02fbe8-20260908", target_is_directory=True
    )

    out_view = view / "out/rk3568"
    out_view.mkdir(parents=True)
    for name in ("gen", "obj", "clang_x64", "clang_arm64"):
        target = output / name
        if target.exists():
            (out_view / name).symlink_to(target, target_is_directory=True)


def redirect_output(argv: list[str], flag: str, destination: Path) -> None:
    if flag not in argv:
        raise ValueError(f"compile command is missing {flag}")
    index = argv.index(flag)
    if index + 1 >= len(argv):
        raise ValueError(f"compile command has no operand after {flag}")
    argv[index + 1] = str(destination)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--profile", required=True, type=Path)
    ap.add_argument("--source-root", required=True, type=Path)
    ap.add_argument("--output-root", required=True, type=Path)
    ap.add_argument("--prebuilts-root", required=True, type=Path)
    ap.add_argument("--toolchain-root", required=True, type=Path)
    ap.add_argument("--evidence-dir", required=True, type=Path)
    ap.add_argument("--source-view", required=True, type=Path)
    ap.add_argument("--timeout-seconds", type=int, default=300)
    ns = ap.parse_args()

    profile_path = ns.profile.resolve()
    source = ns.source_root.resolve()
    output = ns.output_root.resolve()
    prebuilts = ns.prebuilts_root.resolve()
    toolchain = ns.toolchain_root.resolve()
    evidence = ns.evidence_dir.resolve()
    evidence.mkdir(parents=True, exist_ok=False)
    make_source_view(source, prebuilts, toolchain, ns.source_view.resolve(), output)
    compile_cwd = ns.source_view.resolve() / "out/rk3568"

    profile = json.loads(profile_path.read_text(encoding="utf-8"))
    actions = [a for a in profile["runs"][1]["target_source_actions"] if a["target"] == "arm-linux-ohos"]
    if len(actions) != 2:
        raise SystemExit(f"expected 2 ARM product actions, got {len(actions)}")

    records = []
    for index, action in enumerate(actions, 1):
        stem = f"ark-runtime-arm-action-{index}"
        obj = evidence / f"{stem}.o"
        dep = evidence / f"{stem}.d"
        stderr_path = evidence / f"{stem}.stderr"
        argv = list(action["argv"])
        redirect_output(argv, "-o", obj)
        redirect_output(argv, "-MF", dep)
        compiler = (compile_cwd / argv[0]).resolve()
        with stderr_path.open("wb") as stderr:
            try:
                completed = subprocess.run(
                    argv,
                    cwd=compile_cwd,
                    stdout=subprocess.DEVNULL,
                    stderr=stderr,
                    timeout=ns.timeout_seconds,
                    check=False,
                    shell=False,
                )
                returncode = completed.returncode
                timed_out = False
            except subprocess.TimeoutExpired:
                returncode = None
                timed_out = True
        row = {
            "action_index": index,
            "object_output_profile_path": action["object_output"],
            "profile_command_sha256": action["command_sha256"],
            "profile_command_bytes": len(action["command"].encode("utf-8")),
            "compiler_realpath": str(compiler),
            "compiler_sha256": sha256_file(compiler)[0],
            "argv_with_only_output_paths_redirected": argv,
            "returncode": returncode,
            "timed_out": timed_out,
            "object": {"path": str(obj), "exists": obj.is_file()},
            "depfile": {"path": str(dep), "exists": dep.is_file()},
            "stderr": {"path": str(stderr_path), "sha256": sha256_file(stderr_path)[0], "bytes": stderr_path.stat().st_size},
        }
        for key, path in (("object", obj), ("depfile", dep)):
            if path.is_file():
                digest, size = sha256_file(path)
                row[key].update({"sha256": digest, "bytes": size})
        records.append(row)

    report = {
        "schema": "ohscanner.c1.direct-object-compile-observation/v1",
        "status": "completed" if all(r["returncode"] == 0 for r in records) else "partial_or_failed",
        "execution_boundary": "unprivileged WSL process; direct compiler invocation only; no GN/Ninja/project scripts/linker/network calls",
        "isolation_limit": "not executed in the original C1 container; read-only source access was not enforced by a mount, so this is supplemental compile evidence and does not close the product-build gate",
        "source_root": str(source),
        "source_view": str(ns.source_view.resolve()),
        "source_view_mode": "top-level symlink farm; original source and output files were not copied or rewritten by this driver",
        "output_root": str(output),
        "evidence_dir": str(evidence),
        "profile_path": str(profile_path),
        "profile_sha256": sha256_file(profile_path)[0],
        "host_platform": platform.platform(),
        "python": sys.version,
        "timeout_seconds_per_action": ns.timeout_seconds,
        "actions": records,
    }
    destination = evidence / "object_compile_observation.v1.json"
    destination.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({
        "status": report["status"],
        "actions": [{"index": r["action_index"], "returncode": r["returncode"], "timed_out": r["timed_out"],
                     "object_sha256": r["object"].get("sha256"), "depfile_sha256": r["depfile"].get("sha256")}
                    for r in records],
        "observation": str(destination),
    }, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(main())
