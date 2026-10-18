from __future__ import annotations

from hashlib import sha1, sha256
import json
import os
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[3]
OUT = Path(__file__).resolve().parent
FREEZE_PATH = ROOT / "research/experiments/ark-runtime-history-replay-20261018/frozen-contract-start-snapshot.json"
LIVE_FREEZE_PATH = ROOT / "research/deliveries/cpp/ark-runtime-c-line-algorithm-freeze-20261018.json"
RECORD_PATH = ROOT / "research/experiments/ark-runtime-exact-source-20261018/reproduction-record.json"
SOURCES = ROOT / "research/experiments/ark-runtime-exact-source-20261018/sources"
TARGET = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
REPO = "openharmony/arkcompiler_ets_runtime"

freeze = json.loads(FREEZE_PATH.read_text(encoding="utf-8"))
live_freeze = json.loads(LIVE_FREEZE_PATH.read_text(encoding="utf-8"))
prior = json.loads(RECORD_PATH.read_text(encoding="utf-8"))
source_profiles = {entry["commit"]: entry for entry in freeze["source_profiles"]}
inputs = {}
for key, profile_key, filename, role in (
    ("parent", 0, "type-origin-parent.cpp", "vulnerable_parent"),
    ("fix", 1, "type-origin-fix.cpp", "fix_revision"),
):
    profile = freeze["source_profiles"][profile_key]
    binding = prior["inputs"]["type_origin"][key]["input"]
    data = (SOURCES / filename).read_bytes()
    blob = sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    source_sha = sha256(data).hexdigest()
    inputs[key] = {
        "role": role,
        "repository": REPO,
        "commit": profile["commit"],
        "tree": profile["tree"],
        "path": TARGET,
        "blob": profile["target_blob"],
        "creator_blob": profile["creator_blob"],
        "bytes": len(data),
        "recomputed_git_blob": blob,
        "recomputed_source_sha256": source_sha,
        "preserved_source_sha256": binding["source_sha256"],
        "blob_bytes_match": blob == profile["target_blob"] and source_sha == binding["source_sha256"],
        "commit_tree_object_status": "not_confirmed_local_cache",
        "raw_bytes_source": f"research/experiments/ark-runtime-exact-source-20261018/sources/{filename}",
    }

code_path = ROOT / "research/full_scan_20261018/lanes/c"
code_integrity = {}
history_repo = ROOT.parent / "arkruntime-holdout-history"
git_env = dict(os.environ, GIT_NO_LAZY_FETCH="1")

def local_commit_tree(commit: str) -> dict:
    proc = subprocess.run(["git", "cat-file", "commit", commit], cwd=history_repo, env=git_env, capture_output=True, text=True)
    if proc.returncode:
        return {"commit_object": "unavailable_local_no_fetch", "tree_object": "not_checked"}
    first = next((line for line in proc.stdout.splitlines() if line.startswith("tree ")), "")
    tree = first[5:] if first else None
    tree_check = subprocess.run(["git", "cat-file", "-e", tree], cwd=history_repo, env=git_env, capture_output=True)
    return {"commit_object": "present_local", "commit_tree": tree, "tree_object": "present_local" if tree and tree_check.returncode == 0 else "unavailable_local"}

for record in inputs.values():
    check = local_commit_tree(record["commit"])
    check["matches_recorded_tree"] = check.get("commit_tree") == record["tree"]
    record["commit_tree_object_check"] = check

other_history = []
for item in (
    ("exception_parent", "exception-parent.cpp", "00003d3b0a5b2863d9c9677c423d96a72f4c6ae6", "472c9b11722ef5df40bcd6a3e743a5a209bce66b6d3e0f41351da97c6de04a0c", "2e2cebedf5a96fb798144c82296b8b55e2eb60c6", "b3489e3b4202da7fe180e8d6c292d544f5973874", "ecmascript/compiler/slowpath_lowering.cpp"),
    ("exception_fix", "exception-fix.cpp", "5c290f71cae4220b9f1fc93fd18803a8ee995c98", "cd4614fa6a4920d7e2ab850ce027d555421d49f40d99c509b0cab980abb342dc", "c80d853d1b3be23ca999618a199183bc854eaa6a", "c57ae1249050c8e2b9f0046ca630f45e08645cf9", "ecmascript/compiler/slowpath_lowering.cpp"),
    ("exception_fix_regression", "exception-fix-regression.js", "5908e384c00382cd0ec1f7ed92c52e39b84c2e40", "de603593f0f5723f5e0f15ff2735619024bf2ae8248a930418c5720c1aa5620b", "c80d853d1b3be23ca999618a199183bc854eaa6a", "c57ae1249050c8e2b9f0046ca630f45e08645cf9", "test/aottest/unhandle_pending_exception/unhandle_pending_exception.js"),
):
    name, filename, expected_blob, expected_sha, commit, tree, path = item
    data = (SOURCES / filename).read_bytes()
    blob = sha1(b"blob " + str(len(data)).encode() + b"\0" + data).hexdigest()
    digest = sha256(data).hexdigest()
    object_state = local_commit_tree(commit)
    other_history.append({"id": name, "repository": REPO, "commit": commit, "tree": tree, "path": path, "blob": expected_blob, "recomputed_git_blob": blob, "source_sha256": digest, "expected_source_sha256": expected_sha, "bytes": len(data), "blob_bytes_match": blob == expected_blob and digest == expected_sha, "local_commit_tree_check": object_state, "frozen_0_3_1_disposition": "not_analyzed_out_of_scope_separate_probe"})
old_execution_commit = prior.get("executed_workspace_commit")
for path, expected in freeze["implementation_sha256"].items():
    rel = Path(path)
    working_file = ROOT / rel
    working_sha = sha256(working_file.read_bytes()).hexdigest() if working_file.exists() else None
    frozen_sha = None
    if old_execution_commit:
        proc = subprocess.run(
            ["git", "show", f"{old_execution_commit}:{path}"], cwd=ROOT,
            env=git_env, capture_output=True,
        )
        if proc.returncode == 0:
            frozen_sha = sha256(proc.stdout).hexdigest()
    code_integrity[path] = {
        "freeze_sha256": expected,
        "working_tree_sha256": working_sha,
        "executed_workspace_commit": old_execution_commit,
        "executed_commit_file_sha256": frozen_sha,
        "frozen_source_restored": expected == working_sha or expected == frozen_sha,
    }

result = {
    "schema": "ark-runtime-frozen-history-replay-v1",
    "overall_status": "blocked",
    "freeze_manifest": "research/experiments/ark-runtime-history-replay-20261018/frozen-contract-start-snapshot.json",
    "freeze_manifest_sha256": sha256(FREEZE_PATH.read_bytes()).hexdigest(),
    "freeze_snapshot_is_byte_exact": False,
    "live_freeze_at_manifest_generation": {"version": live_freeze.get("detector_version"), "model_sha256": live_freeze.get("model_sha256"), "manifest_sha256": sha256(LIVE_FREEZE_PATH.read_bytes()).hexdigest()},
    "frozen_contract": {k: freeze[k] for k in ("detector", "version", "rule_id", "model_sha256", "freeze_scope")},
    "source_integrity": inputs,
    "other_historical_source_integrity": other_history,
    "frozen_implementation_integrity": code_integrity,
    "replay_command": "python research/experiments/ark-runtime-history-replay-20261018/replay.py",
    "replay_blockers": [
        "One or more 0.3.1 implementation files whose SHA-256 values are in the task-start freeze snapshot are absent from the working tree and do not match the recorded executed-workspace commit; the live freeze and model have since moved to 0.3.2.",
        "The typedarray parent and fix commit/tree objects are unavailable in the local history cache. The original source checkout has an empty .git/config; no fetch was performed.",
        "The frozen NewObjectStubBuilder creator dependency bytes are not present in the preserved source bundle.",
    ],
    "sample_dispositions": {
        "typedarray_parent": {"status": "blocked", "reason": "Frozen implementation and exact commit/tree provenance are not restored; no 0.3.1 replay was run."},
        "typedarray_fix": {"status": "blocked", "reason": "Frozen implementation and exact commit/tree provenance are not restored; no 0.3.1 replay was run."},
        "safe_Set_control": {"status": "blocked", "reason": "In-scope control in fix blob; not run because frozen implementation cannot be restored."},
        "unrelated_Map_control": {"status": "not_analyzed", "reason": "Map is outside the frozen caller profiles; no caller override or custom config was used."},
        "exception_propagation_parent_fix": {"status": "not_analyzed", "reason": "Different file family and separate research-only detector/probe; previous outputs are quarantined and not combined."},
    },
    "expected_parent_fix_difference": "The parent samples the receiver type token before storing into a species-created result; the fix samples the result array type. Under the frozen 0.3.1 semantics the parent is expected to remain a partial candidate, while the fixed source is unknown because the type read occurs before pending-exception handling. That expected difference is not a replay result or safety label.",
    "historical_runs_excluded": [
        {"detector_version": "0.2.0", "model_sha256": prior["model_sha256"], "reason": "Different model and implementation; excluded from current freeze replay."},
        {"detector_version": "0.3.0", "artifact": "research/experiments/ark-runtime-exception-guard-20261018/raw-results.json", "reason": "Earlier exception-guard follow-up; not the frozen 0.3.1 run and not a component-wide label."},
        {"detector": "research.ark.runtime.exception_propagation_probe", "artifact": "research/experiments/ark-runtime-exact-source-20261018/reproduction-record.json", "reason": "Independent lexical probe; not combined with C type-origin results."},
    ],
    "status_semantics": {"candidate": "not emitted in this blocked replay", "partial": "no new detector result", "blocked": "required frozen code or provenance unavailable", "not_analyzed": "out of frozen scope or no valid execution", "failed": "reserved for an attempted analysis that errors; none attempted"},
    "no_accuracy_claim": True,
}
(OUT / "replay-manifest.json").write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
(OUT / "run-summary.json").write_text(json.dumps({"overall_status": result["overall_status"], "sample_dispositions": result["sample_dispositions"], "source_integrity": {k: {"blob_bytes_match": v["blob_bytes_match"], "commit_tree_object_status": v["commit_tree_object_status"]} for k, v in inputs.items()}, "code_restored": all(x["frozen_source_restored"] for x in code_integrity.values()), "blockers": result["replay_blockers"]}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"overall_status": result["overall_status"], "sample_dispositions": result["sample_dispositions"], "blob_bytes_match": {k: v["blob_bytes_match"] for k, v in inputs.items()}, "code_restored": all(x["frozen_source_restored"] for x in code_integrity.values())}, ensure_ascii=False, indent=2))
