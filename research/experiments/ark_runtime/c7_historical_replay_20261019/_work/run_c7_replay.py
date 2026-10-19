from __future__ import annotations

from hashlib import sha256
import json
import os
from pathlib import Path
import subprocess
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[5]
OUT = Path(__file__).resolve().parent
WORK = OUT
REPO = Path(os.environ.get("OHSCANNER_ARK_REPO", r"E:\网安\_oh_targets\arkcompiler_ets_runtime"))
ARK_PYDEPS = Path(os.environ.get("OHSCANNER_PYDEPS", r"E:\网安\_runtime\ohscanner-pydeps"))
BASELINE = "b011ea0cf732e5c07cb9d9fe0ab9ec451e87c5df"

ENV = dict(
    os.environ,
    GIT_NO_LAZY_FETCH="1",
    GIT_ALLOW_PROTOCOL="",
    PIP_NO_INDEX="1",
    PYTHONPATH=os.pathsep.join([str(ROOT), str(WORK / "baseline"), str(ROOT / ".tmp" / "pydeps"), str(ARK_PYDEPS), os.environ.get("PYTHONPATH", "")]).rstrip(os.pathsep),
)

TARGET = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
CREATOR = "ecmascript/compiler/new_object_stub_builder.cpp"


def run(args: list[str], timeout: int = 300) -> dict:
    started = perf_counter()
    proc = subprocess.run(
        args,
        cwd=(WORK / "baseline") if (WORK / "baseline").exists() else ROOT,
        env=ENV,
        text=True,
        encoding="utf-8",
        errors="replace",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return {
        "command": args,
        "exit_code": proc.returncode,
        "elapsed_seconds": round(perf_counter() - started, 6),
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def git(*args: str, timeout: int = 120) -> dict:
    return run(["git", "-C", str(REPO), *args], timeout=timeout)


def verify_object(spec: dict) -> dict:
    result = {
        "id": spec["id"],
        "role": spec["role"],
        "repository_declared": "openharmony/arkcompiler_ets_runtime",
        "object_ref": spec.get("object_ref", spec.get("commit")),
        "path": spec["path"],
        "expected_blob": spec.get("expected_blob"),
        "expected_source_sha256": spec.get("expected_source_sha256"),
        "expected_bytes": spec.get("expected_bytes"),
        "checks": {},
        "status": "failed",
        "assessment": "candidate/unassessed",
    }
    ref = result["object_ref"]
    rev = git("rev-parse", ref + "^{commit}")
    result["checks"]["resolve_commit"] = rev
    if rev["exit_code"] != 0:
        result["fail_closed_reason"] = "commit_ref_unresolved"
        return result
    commit = rev["stdout"].strip()
    result["commit"] = commit
    if spec.get("commit") and commit != spec["commit"]:
        result["fail_closed_reason"] = "resolved_commit_mismatch"
        return result

    typ = git("cat-file", "-t", commit)
    result["checks"]["commit_type"] = typ
    meta = git("show", "-s", "--format=%T%n%P", commit)
    result["checks"]["commit_tree_parents"] = meta
    if typ["exit_code"] != 0 or typ["stdout"].strip() != "commit" or meta["exit_code"] != 0:
        result["fail_closed_reason"] = "commit_or_tree_unavailable"
        return result
    tree, parents = (meta["stdout"].splitlines() + [""])[:2]
    result["tree"] = tree
    result["parents"] = parents.split()
    if spec.get("expected_tree") and tree != spec["expected_tree"]:
        result["fail_closed_reason"] = "tree_mismatch"
        return result
    if spec.get("expected_parent") and spec["expected_parent"] not in result["parents"]:
        result["fail_closed_reason"] = "parent_relation_mismatch"
        return result

    listing = git("ls-tree", commit, "--", spec["path"])
    result["checks"]["ls_tree"] = listing
    if listing["exit_code"] != 0:
        result["fail_closed_reason"] = "path_not_resolved"
        return result
    line = listing["stdout"].strip()
    if not line:
        result["fail_closed_reason"] = "path_absent"
        return result
    metadata, path = line.split("\t", 1)
    _, object_type, blob = metadata.split()
    result["actual_blob"] = blob
    result["actual_path"] = path
    if object_type != "blob":
        result["fail_closed_reason"] = "path_is_not_blob"
        return result
    if spec.get("expected_blob") and blob != spec["expected_blob"]:
        result["fail_closed_reason"] = "blob_mismatch"
        return result

    payload = git("cat-file", "blob", blob, timeout=180)
    result["checks"]["cat_file_blob"] = {
        "command": payload["command"],
        "exit_code": payload["exit_code"],
        "elapsed_seconds": payload["elapsed_seconds"],
        "stderr": payload["stderr"],
        "stdout_chars": len(payload["stdout"]),
    }
    if payload["exit_code"] != 0:
        result["fail_closed_reason"] = "blob_bytes_unavailable_no_lazy_fetch"
        return result
    data = payload["stdout"].encode("utf-8")
    actual_sha = sha256(data).hexdigest()
    result["actual_source_sha256"] = actual_sha
    result["actual_bytes"] = len(data)
    if spec.get("expected_source_sha256") and actual_sha != spec["expected_source_sha256"]:
        result["fail_closed_reason"] = "source_sha256_mismatch"
        return result
    if spec.get("expected_bytes") is not None and len(data) != spec["expected_bytes"]:
        result["fail_closed_reason"] = "byte_length_mismatch"
        return result
    result["status"] = "verified"
    result["fail_closed_reason"] = None
    return result


OBJECTS = [
    {
        "id": "C1_TYPE_ORIGIN_PARENT",
        "role": "parent",
        "commit": "830e85b40240677039719fcbf14f721ad3b19050",
        "expected_tree": "579712c1ebbb703d17cea422b1572023bed5d8a4",
        "path": TARGET,
        "expected_blob": "054451b1be4f39254d56a1683cc9d1c1b5e55018",
        "expected_source_sha256": "847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422",
        "expected_bytes": 150433,
    },
    {
        "id": "C1_TYPE_ORIGIN_FIX",
        "role": "fix",
        "commit": "a0e30483ab3e4aead67ecfb5c708489915e447f9",
        "expected_tree": "82af11ced4297818410ccf61906b703d25b69165",
        "expected_parent": "830e85b40240677039719fcbf14f721ad3b19050",
        "path": TARGET,
        "expected_blob": "95f54f2875f401afe3167c62f8c1e7799782be8c",
        "expected_source_sha256": "8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e",
        "expected_bytes": 150509,
    },
    {
        "id": "EXCEPTION_PATH_PARENT",
        "role": "unknown",
        "commit": "c758818dbfd0b146a908d43d21f6ca1706c33783",
        "expected_tree": "5d7c18a5d5ccbf48617b3c07ae9353f5f427d07a",
        "path": TARGET,
        "expected_blob": "857ad416bc102fcd5d462e9702d2ba7c51f29b6d",
        "expected_source_sha256": "984e45f2b6ea652c412437be03dda4189549afe4cf77c95713cf0d0c5d361db9",
    },
    {
        "id": "EXCEPTION_PATH_FIX",
        "role": "fix",
        "commit": "81ca57487d04ea30cd11c271e86494a4e130f43e",
        "expected_tree": "f0ddee8ee7f74b3f22e45b174ce96a269b2e57a5",
        "expected_parent": "c758818dbfd0b146a908d43d21f6ca1706c33783",
        "path": TARGET,
        "expected_blob": "3b9de9d915d767d7a67316145451da2446162884",
        "expected_source_sha256": "4684a1587519e7d141f181b595317db489991a3908e1f1b4ef67513c25d9efd0",
    },
    {
        "id": "CURRENT_BOUND_CONTROL",
        "role": "safe_control_not_verdict",
        "commit": "a65a2853ccae13da167d9aa4720ab8b11ec16656",
        "path": TARGET,
        "expected_blob": "68fb3b0adc4f9062889a861be51b7be90362e37a",
        "expected_source_sha256": "76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c",
    },
    {
        "id": "CURRENT_UNBOUND_PARENT_CONTROL",
        "role": "unrelated",
        "object_ref": "a65a2853ccae13da167d9aa4720ab8b11ec16656^",
        "path": TARGET,
    },
]

DEPENDENCIES = [
    {"id": "C1_CREATOR_DEPENDENCY", "role": "dependency", "commit": "830e85b40240677039719fcbf14f721ad3b19050", "expected_tree": "579712c1ebbb703d17cea422b1572023bed5d8a4", "path": CREATOR, "expected_blob": "757b8d050d306d349822600deacb295c7a54245e", "expected_source_sha256": "3fd7e99e957fb5b7793cb7c36c01b370208c05645aa93551da6abeecaf2e7198", "expected_bytes": 126036},
    {"id": "EXCEPTION_CREATOR_DEPENDENCY_PARENT", "role": "dependency", "commit": "c758818dbfd0b146a908d43d21f6ca1706c33783", "expected_tree": "5d7c18a5d5ccbf48617b3c07ae9353f5f427d07a", "path": CREATOR, "expected_blob": "05dda56de74949f07a241942be6465beaf94b52a", "expected_source_sha256": "c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e"},
    {"id": "EXCEPTION_CREATOR_DEPENDENCY_FIX", "role": "dependency", "commit": "81ca57487d04ea30cd11c271e86494a4e130f43e", "expected_tree": "f0ddee8ee7f74b3f22e45b174ce96a269b2e57a5", "path": CREATOR, "expected_blob": "05dda56de74949f07a241942be6465beaf94b52a", "expected_source_sha256": "c10e934be1804fe9388d599cba54369eed4ee150b078d04924e0da68a2f43b9e"},
]


def main() -> int:
    WORK.mkdir(parents=True, exist_ok=True)
    results = {
        "schema": "c7-execution-results-v2",
        "baseline": BASELINE,
        "repo": str(REPO),
        "network_used": False,
        "git_no_lazy_fetch": ENV["GIT_NO_LAZY_FETCH"],
        "object_results": [verify_object(x) for x in OBJECTS],
        "dependency_results": [verify_object(x) for x in DEPENDENCIES],
    }

    test_cmd = [sys.executable, str(WORK / "baseline" / "tests" / "detectors" / "ark_runtime" / "test_historical.py"), "-v"]
    test = run(test_cmd, timeout=600)
    (WORK / "unittest.stdout.txt").write_text(test["stdout"], encoding="utf-8")
    (WORK / "unittest.stderr.txt").write_text(test["stderr"], encoding="utf-8")
    results["unittest"] = {k: v for k, v in test.items() if k not in {"stdout", "stderr"}}
    results["unittest"]["stdout_file"] = "_work/unittest.stdout.txt"
    results["unittest"]["stderr_file"] = "_work/unittest.stderr.txt"

    replay_commands = {
        "c2": [sys.executable, "research/experiments/ark_runtime/c2_20261017/replay.py", "--repo-dir", str(REPO), "--output", str(WORK / "c2")],
        "c3": [sys.executable, "research/experiments/ark_runtime/c3_20261017/replay.py", "--repo-dir", str(REPO), "--output", str(WORK / "c3")],
    }
    results["replays"] = {}
    for name, command in replay_commands.items():
        replay = run(command, timeout=900)
        (WORK / f"replay_{name}.stdout.txt").write_text(replay["stdout"], encoding="utf-8")
        (WORK / f"replay_{name}.stderr.txt").write_text(replay["stderr"], encoding="utf-8")
        results["replays"][name] = {k: v for k, v in replay.items() if k not in {"stdout", "stderr"}}
        results["replays"][name]["stdout_file"] = f"_work/replay_{name}.stdout.txt"
        results["replays"][name]["stderr_file"] = f"_work/replay_{name}.stderr.txt"

    all_objects = results["object_results"] + results["dependency_results"]
    results["summary"] = {
        "objects_checked": len(results["object_results"]),
        "dependencies_checked": len(results["dependency_results"]),
        "objects_verified": sum(x["status"] == "verified" for x in results["object_results"]),
        "dependencies_verified": sum(x["status"] == "verified" for x in results["dependency_results"]),
        "object_fail_closed": sum(x["status"] != "verified" for x in results["object_results"]),
        "all_object_bytes_verified": all(x["status"] == "verified" for x in all_objects),
        "unittest_exit_code": test["exit_code"],
        "c2_exit_code": results["replays"]["c2"]["exit_code"],
        "c3_exit_code": results["replays"]["c3"]["exit_code"],
    }
    (WORK / "c7_execution_results.json").write_text(json.dumps(results, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps(results["summary"], indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())