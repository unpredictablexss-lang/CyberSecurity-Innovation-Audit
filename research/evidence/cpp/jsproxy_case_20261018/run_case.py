#!/usr/bin/env python3
"""Run the source-bound JSProxy shared_ptr race harness under TSan."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
HARNESS = ROOT / "harness"
REPEATS = 3


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_variant(name: str, out_dir: Path) -> Path:
    binary = out_dir / ("jsproxy_" + name)
    command = [
        "clang++",
        "-std=c++17",
        "-g",
        "-O1",
        "-fsanitize=thread",
        "-fno-omit-frame-pointer",
        "-pthread",
        "-I",
        str(HARNESS / name),
        str(HARNESS / "harness.cpp"),
        "-o",
        str(binary),
    ]
    subprocess.run(command, check=True)
    return binary


def run_binary(binary: Path, log: Path) -> int:
    environment = os.environ.copy()
    environment.update({
        "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
    })
    command = ["setarch", "x86_64", "-R", str(binary)]
    completed = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=environment,
        text=True,
    )
    log.write_text(completed.stdout, encoding="utf-8")
    return completed.returncode


def main() -> int:
    ROOT.mkdir(parents=True, exist_ok=True)
    results = {"schema_version": 1, "case": "JSProxy::instance_", "repeats": REPEATS, "variants": {}}
    for name in ("vulnerable", "fixed"):
        out_dir = ROOT / "build" / name
        log_dir = ROOT / "logs" / name
        out_dir.mkdir(parents=True, exist_ok=True)
        log_dir.mkdir(parents=True, exist_ok=True)
        binary = compile_variant(name, out_dir)
        runs = []
        for index in range(1, REPEATS + 1):
            log = log_dir / f"run-{index:02d}.log"
            code = run_binary(binary, log)
            runs.append({
                "run": index,
                "exit_code": code,
                "tsan_race": "WARNING: ThreadSanitizer: data race" in log.read_text(encoding="utf-8"),
                "log": str(log.relative_to(ROOT)),
                "log_sha256": sha256(log),
            })
        results["variants"][name] = {
            "header": str((HARNESS / name / "js_proxy.h").relative_to(ROOT)),
            "header_sha256": sha256(HARNESS / name / "js_proxy.h"),
            "binary": str(binary.relative_to(ROOT)),
            "binary_sha256": sha256(binary),
            "runs": runs,
        }
    (ROOT / "results.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    vulnerable = results["variants"]["vulnerable"]["runs"]
    fixed = results["variants"]["fixed"]["runs"]
    ok = all(item["tsan_race"] and item["exit_code"] == 66 for item in vulnerable)
    ok = ok and all(not item["tsan_race"] and item["exit_code"] == 0 for item in fixed)
    print("vulnerable=" + ", ".join(str(item["exit_code"]) for item in vulnerable))
    print("fixed=" + ", ".join(str(item["exit_code"]) for item in fixed))
    print("pass=" + str(ok).lower())
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
