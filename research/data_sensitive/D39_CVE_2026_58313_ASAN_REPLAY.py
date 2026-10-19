#!/usr/bin/env python3
"""Run an isolated ASan concurrency harness against pinned old/fixed LRU headers."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "tests" / "fixtures" / "data_sensitive"
HARNESS = Path(__file__).with_name("D39_CVE_2026_58313_ASAN.cpp")
CASES = {
    "vulnerable": {
        "path": FIXTURES / "d39_cve_2026_58313_lru_vulnerable.h",
        "commit": "7121401db97c3fedba57ae188148249567e09e18",
        "blob": "7ce4262e3f1d2c0173d929318a4795ff1573c721",
    },
    "fixed": {
        "path": FIXTURES / "d39_cve_2026_58313_lru_fixed.h",
        "commit": "d01a9581e35a22c0a58e1e446556ae3d3c189af3",
        "blob": "68114f10d83c8f0bdc46679c7efa35ed286bef8a",
    },
}
ROUNDS = 3


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()


def run_case(cxx: str, name: str, case: dict, build_dir: Path) -> dict:
    header = case["path"]
    data = header.read_bytes()
    blob = git_blob_sha1(data)
    if blob != case["blob"]:
        raise AssertionError(f"{name} fixture Git blob mismatch: {blob}")
    binary = build_dir / f"d39-{name}"
    compile_command = [
        cxx, "-std=c++17", "-O1", "-g", "-fsanitize=address",
        "-fno-omit-frame-pointer", "-pthread", f'-DLRU_HEADER="{header}"',
        str(HARNESS), "-o", str(binary),
    ]
    built = subprocess.run(compile_command, capture_output=True, text=True, timeout=60)
    if built.returncode:
        raise AssertionError(f"{name} compile failed: {built.stderr[-4000:]}")

    runs = []
    for round_id in range(1, ROUNDS + 1):
        env = os.environ.copy()
        env["ASAN_OPTIONS"] = "abort_on_error=1:detect_leaks=0"
        result = subprocess.run([str(binary)], capture_output=True, text=True, env=env, timeout=60)
        combined = result.stdout + result.stderr
        asan_errors = [
            line.strip() for line in combined.splitlines()
            if "ERROR: AddressSanitizer:" in line or "SUMMARY: AddressSanitizer:" in line
        ]
        runs.append({
            "round": round_id,
            "exit_code": result.returncode,
            "asan_errors": asan_errors,
            "completed_message": "completed synthetic concurrent cache workload" in result.stdout,
        })

    if name == "vulnerable" and not all(
        run["exit_code"] != 0 and any("AddressSanitizer:" in line for line in run["asan_errors"])
        for run in runs
    ):
        raise AssertionError(f"vulnerable source did not produce ASan errors in all rounds: {runs}")
    if name == "fixed" and not all(
        run["exit_code"] == 0 and not run["asan_errors"] and run["completed_message"]
        for run in runs
    ):
        raise AssertionError(f"fixed source did not pass cleanly in all rounds: {runs}")

    return {
        "commit": case["commit"],
        "git_blob_sha1": blob,
        "source_sha256": sha256(header),
        "rounds": runs,
        "compile_warning_lines": [
            line.strip() for line in built.stderr.splitlines()
            if "warning:" in line
        ],
    }


def main() -> None:
    cxx = os.environ.get("CXX", "g++")
    compiler = subprocess.check_output([cxx, "--version"], text=True).splitlines()[0]
    harness_sha = sha256(HARNESS)
    with tempfile.TemporaryDirectory(prefix="ohscanner-d39-58313-") as temp:
        build_dir = Path(temp)
        vulnerable = run_case(cxx, "vulnerable", CASES["vulnerable"], build_dir)
        fixed = run_case(cxx, "fixed", CASES["fixed"], build_dir)

    output = {
        "schema": 1,
        "experiment": "CVE-2026-58313 isolated component LRU concurrency harness",
        "compiler": compiler,
        "address_sanitizer": True,
        "harness_sha256": harness_sha,
        "iterations_per_source": ROUNDS,
        "vulnerable": vulnerable,
        "fixed": fixed,
        "component_result": "ASan memory error reproduced on pinned pre-fix source and absent on pinned lock-protected source",
        "product_status": "unknown",
        "finding_status": "candidate",
        "validated_vulnerability": 0,
        "limitations": [
            "This is a standalone component harness using synthetic keys, not an OpenHarmony product build or product PoC.",
            "The observed sanitizer result is a double-free from unsynchronized container operations; it does not establish attacker reachability or product impact.",
            "The upstream fix is applied as a fixed source snapshot; no OpenHarmony release image or affected device was built.",
            "The pinned upstream header emits an unrelated warning because SetMaxCap returns bool without a return statement.",
        ],
    }
    output_path = Path(__file__).with_name("D39_CVE_2026_58313_ASAN_REPLAY.json")
    output_path.write_text(json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(output_path),
        "vulnerable_errors": [run["asan_errors"] for run in vulnerable["rounds"]],
        "fixed_exit_codes": [run["exit_code"] for run in fixed["rounds"]],
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()