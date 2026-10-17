#!/usr/bin/env python3
"""Container-only runner for the CAP-01 render-session capability handoff PoC."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Mapping, Sequence


HERE = Path(__file__).resolve().parent
PACKAGE = HERE.parent
DEFAULT_MANIFEST = PACKAGE / "source-manifest.json"
VARIANTS = ("vulnerable", "fixed_control", "patched")
SCENARIOS = ("unauthorized_export", "authorized_export", "wrong_descriptor", "unknown_screen")
EXPECTED = {
    "vulnerable": {
        "unauthorized_export": True,
        "authorized_export": True,
        "wrong_descriptor": False,
        "unknown_screen": False,
    },
    "fixed_control": {
        "unauthorized_export": False,
        "authorized_export": True,
        "wrong_descriptor": False,
        "unknown_screen": False,
    },
    "patched": {
        "unauthorized_export": False,
        "authorized_export": True,
        "wrong_descriptor": False,
        "unknown_screen": False,
    },
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def run(command: Sequence[str], cwd: Path, timeout: int = 120,
        env: Mapping[str, str] | None = None) -> Dict[str, Any]:
    started = time.monotonic()
    done = subprocess.run(
        list(command), cwd=str(cwd), text=True, capture_output=True,
        timeout=timeout, check=False, env=dict(env) if env is not None else None,
    )
    return {
        "command": list(command), "exit_code": done.returncode,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "stdout": done.stdout, "stderr": done.stderr,
    }


def require_container() -> None:
    if os.environ.get("OHSCANNER_VALIDATION_CONTAINER") != "1" or not Path("/.dockerenv").is_file():
        raise SystemExit(
            "container_required: PoC build/run is allowed only in the isolated Docker validation Worker"
        )


def git_bytes(repo: Path, object_id: str) -> bytes:
    done = subprocess.run(
        ["git", "-C", str(repo), "cat-file", "blob", object_id],
        capture_output=True, check=False,
    )
    if done.returncode != 0:
        raise RuntimeError(f"git cat-file blob {object_id} failed: {done.stderr.decode('utf-8', 'replace')}")
    return done.stdout


def verify_sources(repo: Path, manifest: Mapping[str, Any]) -> Dict[str, Any]:
    identity = run(
        ["git", "-C", str(repo), "rev-parse", "HEAD", "HEAD^{tree}"],
        repo, timeout=30,
    )
    if identity["exit_code"] != 0:
        raise RuntimeError(identity["stderr"] or identity["stdout"])
    values = identity["stdout"].splitlines()
    observed = {"commit": values[0], "tree": values[1], "root_tree": values[1]}
    expected_identity = manifest["repository_identity"]
    for key in ("commit", "tree"):
        if observed[key] != expected_identity[key]:
            raise RuntimeError(f"{key} mismatch: {observed[key]} != {expected_identity[key]}")

    verified: List[Dict[str, Any]] = []
    for item in manifest["sources"]:
        path = item["path"]
        blob = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", f"{expected_identity['commit']}:{path}"],
            capture_output=True, text=True, check=False,
        )
        if blob.returncode != 0:
            raise RuntimeError(f"missing pinned source {path}: {blob.stderr}")
        observed_blob = blob.stdout.strip()
        data = git_bytes(repo, observed_blob)
        digest = sha256(data)
        if observed_blob != item["blob"] or digest != item["sha256"]:
            raise RuntimeError(f"source binding mismatch for {path}")
        verified.append({"path": path, "blob": observed_blob, "bytes": len(data),
                         "sha256": digest, "role": item["role"]})

    relation_results: List[Dict[str, Any]] = []
    by_path = {
        item["path"]: git_bytes(repo, item["blob"]).decode("utf-8").splitlines()
        for item in manifest["sources"]
    }
    for relation in manifest["relations"]:
        observed_line = by_path[relation["path"]][relation["line"] - 1]
        if relation["contains"] not in observed_line:
            raise RuntimeError(
                f"relation quote mismatch at {relation['path']}:{relation['line']}: {observed_line}"
            )
        relation_results.append({**relation, "observed_line": observed_line, "verified": True})
    return {"identity": observed, "sources": verified, "relations": relation_results}


def compiler_version(compiler: str) -> Dict[str, Any]:
    result = run([compiler, "--version"], HERE, timeout=30)
    text = result["stdout"] or result["stderr"]
    return {"command": result["command"], "exit_code": result["exit_code"],
            "first_line": text.splitlines()[0] if text else ""}


def build_variant(compiler: str, variant: str, build_dir: Path) -> Dict[str, Any]:
    macro = {
        "vulnerable": "-DCAP01_VARIANT_VULNERABLE=1",
        "fixed_control": "-DCAP01_VARIANT_FIXED_CONTROL=1",
        "patched": "-DCAP01_VARIANT_PATCHED=1",
    }[variant]
    binary = build_dir / f"cap01_{variant}"
    command = [
        compiler, "-std=c++17", "-O1", "-g", "-fsanitize=undefined",
        "-fno-omit-frame-pointer", macro, str(HERE / "harness.cpp"), "-o", str(binary),
    ]
    result = run(command, HERE, timeout=120)
    result.update({"variant": variant, "binary": str(binary),
                   "binary_sha256": sha256(binary.read_bytes()) if binary.is_file() else None})
    return result


def run_case(binary: Path, scenario: str) -> Dict[str, Any]:
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1:abort_on_error=1"
    env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    result = run([str(binary), scenario], HERE, timeout=30, env=env)
    lines = [line for line in result["stdout"].splitlines() if line.strip()]
    parsed = json.loads(lines[-1]) if lines else {}
    result.update({
        "scenario": scenario,
        "parsed": parsed,
        "sanitizer_detected": any(
            marker in (result["stdout"] + result["stderr"])
            for marker in ("AddressSanitizer", "UndefinedBehaviorSanitizer", "runtime error:")
        ),
    })
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    args = parser.parse_args()

    require_container()
    if args.repeats < 1 or args.repeats > 20:
        raise SystemExit("--repeats must be between 1 and 20")
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    source_verification = verify_sources(args.target, manifest)
    compiler = os.environ.get("CXX", "g++")
    version = compiler_version(compiler)
    if version["exit_code"] != 0:
        raise RuntimeError(f"compiler unavailable: {version}")

    args.out.parent.mkdir(parents=True, exist_ok=True)
    build_dir = args.out.parent / "bin"
    build_dir.mkdir(parents=True, exist_ok=True)
    builds = [build_variant(compiler, variant, build_dir) for variant in VARIANTS]
    if any(item["exit_code"] != 0 for item in builds):
        raise RuntimeError("one or more harness variants failed to build")

    runs: List[Dict[str, Any]] = []
    mismatches: List[Dict[str, Any]] = []
    for variant in VARIANTS:
        binary = Path(next(item["binary"] for item in builds if item["variant"] == variant))
        for repeat in range(1, args.repeats + 1):
            for scenario in SCENARIOS:
                record = run_case(binary, scenario)
                record.update({"variant": variant, "repeat": repeat})
                observed = bool(record.get("parsed", {}).get("exported"))
                expected = EXPECTED[variant][scenario]
                record["expected_exported"] = expected
                record["matches_expected"] = (record["exit_code"] == 0 and bool(record["parsed"]) and observed == expected and not record["sanitizer_detected"])
                if not record["matches_expected"]:
                    mismatches.append({"variant": variant, "repeat": repeat,
                                       "scenario": scenario, "expected": expected,
                                       "observed": observed})
                runs.append(record)

    result = {
        "schema_version": "ohscanner.cap01-render-session-poc.v1",
        "candidate_status": "candidate/unknown",
        "validated_vulnerability": 0,
        "product_dynamic_validation": False,
        "component_model_dynamic_validation": not mismatches,
        "stable_replay": not mismatches and args.repeats >= 3,
        "source_verification": source_verification,
        "environment": {
            "container_required": True,
            "ohscanner_validation_container": os.environ.get("OHSCANNER_VALIDATION_CONTAINER"),
            "dockerenv": Path("/.dockerenv").is_file(),
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "compiler": version,
        },
        "sanitizers": ["undefined"],
        "compile_flags": ["-std=c++17", "-O1", "-g", "-fsanitize=undefined", "-fno-omit-frame-pointer"],
        "builds": builds,
        "runs": runs,
        "mismatches": mismatches,
        "repeats": args.repeats,
        "limitations": [
            "This is a component model of the pinned dispatch and capability handoff path, not an OpenHarmony product build.",
            "It proves only the modeled authorization difference; product service acquisition, SELinux/samgr policy and real render-session capabilities remain unknown.",
            "No live service, device, network endpoint or production process is contacted.",
        ],
    }
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"out": str(args.out),
                      "component_model_dynamic_validation": result["component_model_dynamic_validation"],
                      "stable_replay": result["stable_replay"],
                      "mismatches": len(mismatches)}, sort_keys=True))
    return 0 if not mismatches else 1


if __name__ == "__main__":
    raise SystemExit(main())
