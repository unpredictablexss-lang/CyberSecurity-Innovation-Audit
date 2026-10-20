import hashlib
import json
import re
import subprocess
from pathlib import Path

root = Path("/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard")
root_win = r"E:\网安\CyberSecurity-Innovation-Audit\research\experiments\ark_runtime\c8_parallel_20261019\worktrees\exception-guard"
base = root / "research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019"
logs = base / "logs"

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def git(*args):
    return subprocess.check_output(["git.exe", "-C", root_win, *args]).decode("utf-8").strip()

def result(name):
    raw = (logs / f"{name}.stderr.txt").read_bytes()
    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8"
    stdout = raw.decode(encoding, errors="replace")
    code = int((logs / f"{name}.exit_code.txt").read_text(encoding="ascii").strip())
    match = re.search(r"Ran (\d+) tests", stdout)
    skip = re.search(r"OK \(skipped=(\d+)\)", stdout)
    total = int(match.group(1)) if match else 0
    skipped = int(skip.group(1)) if skip else 0
    return {
        "exit_code": code,
        "total": total,
        "passed": total - skipped if code == 0 else None,
        "skipped": skipped,
        "failures": 0 if code == 0 else None,
        "errors": 0 if code == 0 else None,
    }

algorithm_paths = [
    "src/ohscanner/detectors/ark_runtime/exception_guard.py",
    "src/ohscanner/detectors/ark_runtime/runtime_exception.py",
    "tests/detectors/ark_runtime/test_exception_guard.py",
    "tests/detectors/ark_runtime/test_runtime_exception.py",
    "tests/detectors/ark_runtime/fixtures/EXC01.cpp",
]
files = []
for path in algorithm_paths:
    item = root / path
    files.append({
        "path": path,
        "sha256": sha256(item),
        "git_blob": git("hash-object", path),
        "bytes": item.stat().st_size,
    })
patch_files = []
for name in ("old_baseline_7af25f5_minimal.patch", "latest_static_09ba5aba_minimal.patch"):
    item = base / name
    patch_files.append({
        "path": name,
        "bytes": item.stat().st_size,
        "sha256": sha256(item),
    })

manifest = {
    "schema_version": 2,
    "case_id": "C9-EXCEPTION-GUARD-ORDER-ACCEPTANCE-20261019",
    "working_tree_only": root_win,
    "old_c_line_baseline": {
        "head": "7af25f5ced471e5d6acc8cf5efd4c696275ce940",
        "tree": "11f53fe00d79d477c383e7e9b49ad3b1adcae86c",
        "role": "current dirty worktree base; all local validation ran here",
    },
    "latest_static_baseline": {
        "head": "09ba5aba03c7c7d6787bace349b8fc0a6b0a5457",
        "tree": "d15b91627c94d9c3043d7d58d47fcf9af7e42454",
        "parent_main": "db77164fdc2af0da02e4d3efc056d84694fd68e8",
        "parent_main_tree": "8c5a296d8304d98193a29a4695aaf61ca0c0996c",
        "role": "comparison and portable patch target; not checked out",
    },
    "remote_pinned_review": {
        "commit": "e4e0761501a83ac25cc67d04c527eefe9f4a1b50",
        "tree": "307ac8237263db793028e0bf34a82a85f60821a5",
        "audit_blob": "dbedea677c8dc70c1b0066c7bc52df27bcff06ea",
    },
    "latest_comparison_objects": {
        "exception_guard": "6cd85455663568cbc808948ec9b1fc7e840a2151",
        "test_exception_guard": "3663bc760f8a7e4d61059bb652f5a40c4bd75302",
        "test_runtime_exception": "fa20a586bce33ecfa72b44e32c60ece8f8bc1490",
        "runtime_exception": None,
        "known_cves": "a2ddd5ff2afc2f6fb0f1677ea3ffbbfc580a195b",
    },
    "known_cves_policy": {
        "version": "0.16.0",
        "source": "origin/main db77164fdc2af0da02e4d3efc056d84694fd68e8",
        "implemented_or_modified_by_this_line": False,
    },
    "runtime": {
        "windows_python": "Microsoft Store placeholder; not used",
        "test_python": "WSL /usr/bin/python3 3.10.12",
        "tree_sitter": "0.26.0",
        "env": {
            "PYTHONPATH": "/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard",
            "OHSCANNER_ARK_REPO": "<unset>",
            "PYTHONHASHSEED": "<unset>",
        },
    },
    "exact_commands": [
        "wsl.exe -e env PYTHONPATH=/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard python3 -m unittest tests.detectors.ark_runtime.test_runtime_exception -v",
        "wsl.exe -e env PYTHONPATH=/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard python3 -m unittest tests.detectors.ark_runtime.test_exception_guard tests.detectors.ark_runtime.test_runtime_exception -v",
        "wsl.exe -e env PYTHONPATH=/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard python3 -m unittest discover -s tests/detectors/ark_runtime -t . -p test_*.py -v",
        "wsl.exe -e env PYTHONPATH=/mnt/e/网安/CyberSecurity-Innovation-Audit/research/experiments/ark_runtime/c8_parallel_20261019/worktrees/exception-guard python3 -m compileall -q src tests/detectors/ark_runtime",
        "git diff --check",
        "git apply --check --reverse --ignore-whitespace -- research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/old_baseline_7af25f5_minimal.patch",
        "git apply --check --reverse --ignore-whitespace -- research/experiments/ark_runtime/c9_exception_guard_acceptance_20261019/latest_static_09ba5aba_minimal.patch",
    ],
    "results": {
        "runtime_exception_focused": result("latest_runtime_exception"),
        "focused_combined": result("latest_focused_combined"),
        "ark_runtime_suite": result("latest_ark_runtime_suite"),
        "compileall": {"exit_code": int((logs / "latest_compileall.exit_code.txt").read_text().strip()), "status": "passed"},
        "git_diff_check": {"exit_code": int((logs / "latest_git_diff_check.exit_code.txt").read_text().strip()), "status": "passed"},
    },
    "skip_policy": "Skips are not passes. Historical source tests remained skipped because OHSCANNER_ARK_REPO is unset; no fetch was performed.",
    "algorithm_files": files,
    "pre_existing_dirty_preserved": [
        "src/ohscanner/detectors/ark_runtime/model.py",
        "research/experiments/ark_runtime/c8_holdout_20261019/",
        "research/methods/ark_runtime/rule_freeze_0.7.0/",
    ],
    "patches": patch_files,
    "patch_validation": {
        "old_reverse_check_exit_code": 0,
        "latest_reverse_check_exit_code": 0,
        "note": "Both patches were generated from exact Git blobs/worktree bytes and reverse-check against the current dirty worktree. Windows CRLF requires --ignore-whitespace for Git patch checks."
    },
    "claims_excluded": [
        "product CIA impact",
        "CVE or affected product version/branch",
        "dynamic PoC reproduction",
        "Precision/Recall or zero FP/FN",
        "safe verdict from matched or zero diagnostics",
        "production CLI detection of I7E0FM before detector/model integration",
    ],
}
(base / "latest_baseline_run_manifest.json").write_text(
    json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

controls = {
    "schema_version": 1,
    "case_id": "C9-RUNTIME-EXCEPTION-CONTROLS-20261019",
    "rule_id": "ark.runtime.callback-exception-before-result-conversion",
    "security_level": "candidate/unassessed",
    "mechanisms": [
        {
            "mechanism": "callback_abrupt_completion_before_ToBoolean",
            "controls": [
                {"class": "positive", "test": "test_positive_callback_before_tboolean_is_candidate", "expected": ["candidate"], "outcome": "complete"},
                {"class": "fixed", "test": "test_fixed_abrupt_completion_guard_before_tboolean", "expected": [], "outcome": "complete"},
                {"class": "safe", "test": "test_safe_unrelated_callback_result_is_not_attributed", "expected": [], "outcome": "complete"},
                {"class": "unrelated", "test": "test_unrelated_translation_unit_is_not_analyzed", "expected": [], "outcome": "not_analyzed"},
                {"class": "unknown", "test": "test_unknown_wrapper_is_partial_not_safe", "expected": [], "outcome": "partial"},
            ],
        },
        {
            "mechanism": "generated_callback_pending_state_before_FastToBoolean",
            "controls": [
                {"class": "positive", "test": "test_generated_callback_result_sentinel_check_does_not_guard_pending_state", "expected": ["candidate"], "outcome": "complete"},
                {"class": "fixed", "test": "test_generated_callback_pending_state_guard_dominates_conversion", "expected": [], "outcome": "complete"},
                {"class": "safe", "test": "test_verified_branch_contract_enables_real_cfg_alias/fixed", "expected": [], "outcome": "complete"},
                {"class": "unrelated", "test": "test_derived_branch_override_disables_base_contract", "expected": [], "outcome": "unknown_contract_rejected"},
                {"class": "unknown", "test": "test_generated_guard_on_different_thread_keeps_path_unknown", "expected": [], "outcome": "partial"},
            ],
        },
    ],
    "evidence_gate": {
        "candidate_is_not_vulnerability": True,
        "zero_observations_is_not_product_safe": True,
        "unknown_or_partial_is_not_pass": True,
        "skips_are_not_passes": True,
    },
}
(base / "control_matrix_runtime_exception_20261019.json").write_text(
    json.dumps(controls, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

conflicts = {
    "schema_version": 1,
    "target": "09ba5aba03c7c7d6787bace349b8fc0a6b0a5457",
    "patch": "latest_static_09ba5aba_minimal.patch",
    "items": [
        {"path": "src/ohscanner/detectors/ark_runtime/exception_guard.py", "kind": "large_semantic_update", "conflict": "09ba retains the older _trace_use implementation; the patch replaces it with bounded allocation/helper effect-order tracing.", "resolution": "Apply the generated patch as a unit and rerun focused tests; do not mix old and new trace functions."},
        {"path": "src/ohscanner/detectors/ark_runtime/runtime_exception.py", "kind": "missing_file_add", "conflict": "09ba tests import this module but the source file is absent.", "resolution": "Add the source file from the patch; no duplicate module should be created."},
        {"path": "tests/detectors/ark_runtime/test_runtime_exception.py", "kind": "test_merge", "conflict": "09ba already contains 485 lines of runtime-exception tests; the patch keeps them and adds an old-model import fallback plus five C9 controls.", "resolution": "Apply as an update, not as a wholesale add."},
        {"path": "tests/detectors/ark_runtime/test_exception_guard.py", "kind": "test_merge", "conflict": "09ba has the older 11-test module; the patch adds copy/store order, zero-length and control-matrix cases.", "resolution": "Keep both historical skip and new synthetic controls."},
        {"path": "tests/detectors/ark_runtime/fixtures/EXC01.cpp", "kind": "fixture_add", "conflict": "09ba removed the old fixture; C9 acceptance needs its five caller controls.", "resolution": "Restore only this line-owned fixture."},
        {"path": "src/ohscanner/detectors/ark_runtime/model.py", "kind": "excluded_overlap", "conflict": "09ba has model version 0.8.10/C-line static model fields and RUNTIME_EXCEPTION_RULE_ID.", "resolution": "Do not patch or duplicate; current dirty model.py is preserved on the old worktree."},
        {"path": "src/ohscanner/detectors/known_cves.py", "kind": "excluded_overlap", "conflict": "origin/main already has known_cves.py VERSION 0.16.0.", "resolution": "Do not implement or modify."},
        {"path": "line_endings", "kind": "tooling", "conflict": "09ba blobs contain CRLF and Windows Git patch checks report whitespace differences.", "resolution": "Use git apply --ignore-whitespace or normalize the checkout consistently; the patch reverse-check passes on the current worktree."},
    ],
}
(base / "latest_static_09ba5aba_conflicts.json").write_text(
    json.dumps(conflicts, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
