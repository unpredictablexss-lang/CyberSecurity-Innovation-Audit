#!/usr/bin/env python3
"""Hash and summarize the C1 isolated Ninja target-build attempt."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROFILE = HERE / "product_profile_20261019.v1.json"
ATTEMPT = HERE / "ninja_isolated_build_20261019" / "attempt2"
SCRIPT = HERE / "run_ninja_targets_isolated_20261019.sh"
OUT = HERE / "ninja_isolated_build_20261019" / "observation.v1.json"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    boundary = (ATTEMPT / "execution_boundary.txt").read_text(encoding="utf-8")
    log = (ATTEMPT / "target-1.log").read_text(encoding="utf-8", errors="replace")
    status = (ATTEMPT / "target-1.status").read_text(encoding="utf-8")
    targets = [row for row in profile["runs"][0]["target_source_actions"] if row.get("target") == "arm-linux-ohos"]
    if len(targets) != 2:
        raise SystemExit(f"expected two exact-profile ARM actions; found {len(targets)}")
    rc_match = re.search(r"^returncode=(\d+)$", status, re.MULTILINE)
    if not rc_match:
        raise SystemExit("target-1 status has no return code")

    mount = {}
    for name in ("root_mount", "source_mount", "prebuilts_mount", "toolchain_mount", "source_view_mount", "output_mount", "evidence_mount"):
        match = re.search(rf"^{name}=(.*)$", boundary, re.MULTILINE)
        mount[name] = match.group(1) if match else None
    options = {name: value.rsplit(None, 1)[-1] if value else "" for name, value in mount.items()}
    network = re.search(r"^namespace_network=(.*)$", boundary, re.MULTILINE)
    py_sha = re.search(r"^python_sha256=(\w+)$", boundary, re.MULTILINE)
    py_version = re.search(r"^python_version=(.*)$", boundary, re.MULTILINE)
    warnings = sum("ninja: warning: multiple rules generate" in line for line in log.splitlines())
    progress = re.search(r"^\[(\d+)/(\d+)\]", log, re.MULTILINE)
    failure = next((line.strip() for line in log.splitlines() if "Read-only file system" in line), None)
    result = {
        "schema": "ohscanner.c1.isolated-ninja-target-build-observation/v1",
        "status": "blocked_before_target_compile",
        "product": profile["product"],
        "profile_digest_sha256": profile["profile_digest_sha256"],
        "source_manifest_sha256": profile["snapshot"]["resolved_manifest_sha256"],
        "ark_runtime_commit": profile["snapshot"]["ark_runtime_commit"],
        "ninja_sha256": profile["profile_digest_inputs"]["tools"]["ninja"],
        "ninja_version": next((line.split("=", 1)[1] for line in boundary.splitlines() if line.startswith("ninja_version=")), None),
        "python_sha256": py_sha.group(1) if py_sha else None,
        "python_expected_sha256": profile["profile_digest_inputs"]["tools"]["python3.12"],
        "python_version": py_version.group(1) if py_version else None,
        "execution_boundary": {
            "user_mount_network_namespaces": True,
            "network_namespace": network.group(1) if network else None,
            "source_read_only": bool(re.search(r"(^|,)ro(,|$)", options["source_mount"])) and bool(re.search(r"(^|,)ro(,|$)", options["source_view_mount"])),
            "prebuilts_read_only": bool(re.search(r"(^|,)ro(,|$)", options["prebuilts_mount"])),
            "toolchain_read_only": bool(re.search(r"(^|,)ro(,|$)", options["toolchain_mount"])),
            "output_writable": bool(re.search(r"(^|,)rw(,|$)", options["output_mount"])),
            "root_filesystem_read_only": bool(re.search(r"(^|,)ro(,|$)", options["root_mount"])),
            "mounts": mount,
        },
        "ninja_command": ["/home/deepsleep/c-line-c1-profile-20261018/toolchain-20261019/ninja", "-C", "/home/deepsleep/c-line-c1-profile-20261018/c1-object-source-view-20261019/out/rk3568", "-j2", "-w", "dupbuild=warn", targets[0]["object_output"]],
        "exact_arm_targets": [{"object_output": row["object_output"], "command_sha256": row["command_sha256"]} for row in targets],
        "attempted_target": targets[0]["object_output"],
        "target_returncode": int(rc_match.group(1)),
        "second_arm_target_attempted": False,
        "target_compile_observed": bool(progress and int(progress.group(1)) > 0 and "builtins_typedarray_stub_builder.o" in log and "FAILED:" not in log),
        "graph_actions_scheduled": int(progress.group(2)) if progress else None,
        "graph_actions_started_before_failure": int(progress.group(1)) if progress else None,
        "duplicate_output_warning_count": warnings,
        "failure": failure,
        "failure_classification": "Ninja prerequisite notice generator attempted to write a source-tree COPYRIGHT file; read-only source mount rejected the write",
        "ninja_logs_sha256": sha(ATTEMPT / "target-1.log"),
        "ninja_sha256_verified_by_runner_preflight": profile["profile_digest_inputs"]["tools"]["ninja"],
        "ninja_status_sha256": sha(ATTEMPT / "target-1.status"),
        "execution_boundary_sha256": sha(ATTEMPT / "execution_boundary.txt"),
        "target_query_sha256": sha(ATTEMPT / "query-target-1.log"),
        "stamp_query_sha256": sha(ATTEMPT / "query-stamp.log"),
        "runner_sha256": sha(SCRIPT),
        "limitations": [
            "The WSL root filesystem remained writable; source, prebuilt, compiler toolchain, and source view were read-only; only GN output and evidence mounts were writable.",
            "Ninja's object target has an order-only inputdeps stamp whose transitive closure schedules unrelated notice/info actions before compiling the requested object.",
            "The exact immutable source policy was preserved; the write failure was not bypassed by making the source tree writable or editing generated Ninja rules.",
            "The second ARM object target was not attempted; no product image build was performed.",
        ],
    }
    if result["target_returncode"] == 0 or result["python_sha256"] != result["python_expected_sha256"]:
        raise SystemExit("observed run does not match the expected blocked exact-profile attempt")
    OUT.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": result["status"], "output": str(OUT), "warnings": warnings, "failure": failure, "sha256": sha(OUT)}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
