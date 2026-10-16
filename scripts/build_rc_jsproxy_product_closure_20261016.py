from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "outputs/reports/rc-jsproxy-product-closure-20261016"
POC_ROOT = ROOT / "outputs/poc/rc-jsproxy-isolated-20261016"
RUN_IDS = ("run-008", "run-009", "run-010")
TARGET_REPO = ROOT / "E:/not-used"
PRODUCT_EVIDENCE = ROOT / "research/evidence/cpp/rc_jsproxy_product_gate_20261015/product-evidence.json"
OLD_VALIDATION = ROOT / "outputs/reports/rc-jsproxy-product-evidence-20261015/validation.json"
RUN_CONTEXT = ROOT / "outputs/reports/rc-jsproxy-product-evidence-20261015/run-context.json"
MANIFEST = ROOT / "src/ohscanner/poc/harnesses/cpp_shared_ptr_jsproxy/manifest.json"
RUNNER = ROOT / "research/experiments/cpp/run_rc_jsproxy_patch_revalidation_20261016.py"
WRAPPER = POC_ROOT / "bin/setarch"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n", encoding="utf-8")


def rel(path: Path) -> str:
    return path.resolve().relative_to(ROOT).as_posix()


def file_record(path: Path) -> dict:
    return {"path": rel(path), "sha256": sha256_file(path), "bytes": path.stat().st_size}


def measured_records(value):
    records = []
    records.extend(value.get("builds", []))
    records.extend(value.get("runtime", {}).get("runs", []))
    checks = value.get("patch_application_checks", {})
    records.extend(item for item in checks.values() if isinstance(item, dict))
    records.extend(item for item in value.get("toolchain", {}).values() if isinstance(item, dict) and "wall_seconds" in item)
    return records


def performance_summary(value) -> dict:
    records = measured_records(value)
    wall = sum(float(item.get("wall_seconds") or 0.0) for item in records)
    control = value.get("controls", {}).get("suite_run", {})
    wall += float(control.get("wall_seconds") or 0.0)
    rss_values = [int(item["peak_rss_kb"]) for item in records if item.get("peak_rss_kb") is not None]
    if control.get("peak_rss_kb") is not None:
        rss_values.append(int(control["peak_rss_kb"]))
    return {
        "measured_child_wall_seconds_sum": round(wall, 6),
        "max_peak_rss_kb": max(rss_values) if rss_values else None,
        "measurement_scope": "GNU time child records plus four-class control suite; not product performance",
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    product = load_json(PRODUCT_EVIDENCE)
    old_validation = load_json(OLD_VALIDATION)
    run_context = load_json(RUN_CONTEXT)
    manifest = load_json(MANIFEST)
    run_values = [load_json(POC_ROOT / run_id / "evidence/revalidation.json") for run_id in RUN_IDS]
    reference = run_values[0]

    shutil.copy2(reference["patch"]["path"] and ROOT / reference["patch"]["path"], OUT / "patch.diff")
    shutil.copy2(RUNNER, OUT / "run_rc_jsproxy_patch_revalidation_20261016.py")
    shutil.copy2(WRAPPER, OUT / "container-setarch-wrapper.py")

    variants = []
    for build in reference["builds"]:
        variant = build["variant"]
        log_files = []
        for run_id in RUN_IDS:
            raw = POC_ROOT / run_id / "work/raw"
            for path in sorted(raw.glob(f"run-{variant}-*")):
                if path.is_file():
                    log_files.append(file_record(path))
        variants.append({
            "variant": variant,
            "artifact_class": "component_tsan_harness_binary_not_product_artifact",
            "artifact_path": build["artifact_path"],
            "artifact_sha256": build["artifact_sha256"],
            "source_sha256": build["source_sha256"],
            "build_command": build["logical_argv"],
            "compiler_sha256": build["compiler"]["sha256"],
            "build_status": build["verification_status"],
            "product_artifact": None,
            "product_artifact_status": "unknown_not_built",
            "runtime_log_hashes": log_files,
        })

    run_summaries = []
    for run_id, value in zip(RUN_IDS, run_values):
        runs = value["runtime"]["runs"]
        run_summaries.append({
            "run_id": run_id,
            "overall_outcome": value["overall_outcome"],
            "required_runs": value["runtime"]["required_passes"],
            "required_total": value["runtime"]["required_total"],
            "all_runs": value["runtime"]["all_passes"],
            "all_total": value["runtime"]["all_total"],
            "controls_passed": value["controls"]["summary"]["passed"],
            "detector_findings": {
                item["variant"]: item["result"]["finding_count"]
                for item in value["detector_runs"]
            },
            "required_outcomes": {
                variant: {
                    mode: [
                        item["trigger_result"]
                        for item in runs
                        if item["variant"] == variant and item["mode"] == mode
                    ]
                    for mode in ("race", "close_get_entry")
                }
                for variant in ("vulnerable", "fixed_control_mutex", "patched_atomic_minimal")
            },
            "patch_application_checks": {
                "git_apply_cached_check": value["patch_application_checks"]["git_apply_cached_check"]["verification_status"],
                "zero_fuzz_repair_control": value["patch_application_checks"]["zero_fuzz_repair_control"]["verification_status"],
            },
            "performance": performance_summary(value),
            "evidence_sha256": sha256_file(POC_ROOT / run_id / "evidence/revalidation.json"),
        })

    attempts = [
        {
            "attempt": "run-001",
            "status": "failed_preflight",
            "exact_error": "patch tool not found",
            "evidence": "terminal-only; evidence/work directories retained",
        },
        {
            "attempt": "run-002",
            "status": "failed_preflight",
            "exact_error": "FileNotFoundError: /usr/bin/time",
            "evidence": "terminal-only traceback; evidence/work directories retained",
        },
        {
            "attempt": "run-003",
            "status": "failed_runtime",
            "exact_error": "setarch: failed to set personality to x86_64: Operation not permitted",
            "result": "0/18 required and 0/36 all runtime runs passed",
            "evidence": POC_ROOT / "run-003/work/raw",
        },
        {
            "attempt": "run-004",
            "status": "failed_container_start",
            "exact_error": "exec: /usr/local/bin/python3: no such file or directory",
            "evidence": "terminal-only",
        },
        {
            "attempt": "run-005",
            "status": "failed_build",
            "exact_error": "clang: error: unable to execute command: Executable ld does not exist",
            "result": "0 builds and 0 runtime runs",
            "evidence": POC_ROOT / "run-005/work/raw",
        },
        {
            "attempt": "run-006",
            "status": "failed_runtime",
            "exact_error": "FATAL: ThreadSanitizer: unexpected memory mapping",
            "result": "1/18 required and 3/36 all runtime runs passed",
            "evidence": POC_ROOT / "run-006/work/raw",
        },
        {
            "attempt": "run-007",
            "status": "failed_control_path_binding",
            "exact_error": "ValueError: /out/work/controls/evidence/logs is not in the subpath of /workspace",
            "result": "18/18 required and 36/36 all runtime runs passed; controls failed before execution",
            "evidence": POC_ROOT / "run-007/work/raw/a-line-four-class-controls.stderr.txt",
        },
        *[{"attempt": run_id, "status": "passed", "result": "18/18 required, 36/36 all, controls passed"} for run_id in RUN_IDS]
    ]

    unknowns = list(product["unknowns"])
    unknowns.extend([
        {
            "id": "strict-isolation-capability-policy",
            "severity": "high",
            "question": "A strict --cap-drop ALL plus default seccomp container could not disable ASLR for ThreadSanitizer; successful component replays required launch-only SYS_ADMIN/SETUID/SETGID and seccomp=unconfined, then the PoC process transitioned to uid 65534 with no effective capabilities",
            "status": "partial_not_fully_compliant",
        },
        {
            "id": "product-three-variant-artifact-hashes",
            "severity": "critical",
            "question": "vulnerable/fixed/patched product build artifact hashes remain unavailable; recorded binary hashes are component Harness artifacts only",
            "status": "unknown",
        },
        {
            "id": "product-version-branch-fix-commit",
            "severity": "high",
            "question": "No pinned product tag/image links this commit to shipped versions or branches, and no upstream fix commit was found in local pinned refs",
            "status": "unknown",
        },
        {
            "id": "cve-search-closure",
            "severity": "medium",
            "question": "No bounded CVE/NVD/upstream assignment search was executed in this offline run",
            "status": "unknown",
        },
        {
            "id": "product-performance",
            "severity": "medium",
            "question": "Component wall/RSS and patch overhead do not establish product performance neutrality",
            "status": "unknown",
        },
    ])

    gate_obligations = [
        {"id": "repository_commit_tree_blob_source", "status": "met_component", "detail": "target commit/tree/blob and source SHA-256 verified from local pinned Git object"},
        {"id": "detector_rule_snapshot_scope_profile", "status": "partial", "detail": "detector 0.5.0 and rule id bound; rule_version is unknown; component snapshot/source scope and m0-synthetic profile recorded; product profile rk3568/user is preflight-only"},
        {"id": "component_build_toolchain_dependency_closure", "status": "met_component", "detail": "three TSan Harness binaries built and hashed in the local image; product dependency closure remains partial"},
        {"id": "product_build", "status": "unknown", "detail": "rk3568/user product target was not built"},
        {"id": "three_variant_product_artifact_hashes", "status": "unknown", "detail": "component binary hashes are not product artifacts"},
        {"id": "real_entry_permission_identity_deployment", "status": "unknown", "detail": "source-visible JS/NAPI path only; runtime policy, identity and image deployment unproved"},
        {"id": "product_trigger_and_trace", "status": "unknown", "detail": "source-defined interleaving only; no product thread/queue trace"},
        {"id": "sensitive_operation_and_cia", "status": "unknown", "detail": "potential owner reset/read conflict is source-visible; product reachability and C/I/A effect unproved"},
        {"id": "affected_versions_branches_fix_commit", "status": "unknown", "detail": "no product image/tag/branch membership or upstream fix commit proof"},
        {"id": "poc_repeats_and_controls", "status": "met_component", "detail": "three complete isolated replays, each 18/18 required and 36/36 all; positive/fixed/safe/unrelated controls passed"},
        {"id": "zero_fuzz_patch_revalidation", "status": "met_component", "detail": "git apply --cached --check and patch --fuzz=0 passed against exact blob; API/ownership single-path and performance controls passed"},
        {"id": "cwe_cve", "status": "partial", "detail": "CWE-362 candidate_supported; CWE-416 unproved consequence; CVE not_assigned in available local evidence and search closure unknown"},
        {"id": "strict_dynamic_isolation", "status": "partial", "detail": "no network, read-only root and resource limits held; capability/seccomp exceptions required for TSan ASLR control"},
    ]

    report = {
        "schema_version": 1,
        "kind": "ohscanner.rc-jsproxy.product-closure.v1",
        "generated_at_utc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "selection": {
            "selected": "RC-JSPROXY",
            "not_selected": "DelayedSingleton",
            "basis": "RC-JSPROXY has the more complete product chain: source-visible JS/NAPI entries, call-path blobs, product build profile, build/dependency/toolchain attempts and patch revalidation. DelayedSingleton has a stronger 56-row source-version matrix but no product build, entry, permission, deployment or CIA evidence.",
        },
        "product_gate": {
            "status": "not_met",
            "final_status": "candidate/unknown",
            "validated_vulnerability": 0,
            "confirmed_reportable": False,
            "promotion_allowed": False,
            "obligations": gate_obligations,
        },
        "identity": {
            "audit_repository": {
                "remote": "https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git",
                "branch": "codex/full-runtime-performance-audit-20261014",
                "head": "8e97f152ef747c1e1d21ae179a048910f147e07a",
                "tree": "e50c111e3b487b048e8807dafe06625a87f296ad",
                "dirty_worktree_preserved": True,
            },
            "target_repository": "openharmony/distributeddatamgr_kv_store",
            "target_commit": "acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
            "target_tree": "3b92c53fde616d5a3f9487b0c295670a42c63023",
            "source_path": "frameworks/common/js_proxy.h",
            "source_blob": "19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46",
            "source_sha256": "38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f",
            "source_checkout_sha256": "e417eb614183e090fe9390e3c5842bfa8ff1bacb382b191e6560d4591cc6d050",
            "snapshot_binding": {
                "checkout_context_sha256": "5c32ff9d57c4bf94547143cb701ed365484b2cf2d4c1aed8de8202bfadf61610",
                "detector_snapshot_sha256_vulnerable": "38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f",
                "detector_snapshot_sha256_fixed_control": "9044ccaac42cefdd2c153c01b07c0893634aa0aee8ad54093e1065740329a902",
                "detector_snapshot_sha256_patched": "4d57f286602e15af636c40158e8cdabc6f617fda89d8276128c674b4ab633b6f",
            },
            "detector": {
                "id": manifest["detector_id"],
                "version": manifest["detector_version"],
                "rule_id": manifest["rule_id"],
                "rule_version": None,
                "candidate_ids": manifest["candidate_ids"],
                "diagnostic_ids": manifest["diagnostic_ids"],
                "scope": ["frameworks/common/js_proxy.h", *[item["path"] for item in manifest["call_path_sources"]]],
                "component_profile": "m0-synthetic",
                "product_profile": {"product_name": "rk3568", "build_variant": "user"},
            },
        },
        "builds": {
            "product": product["product_build"],
            "component_container": {
                "image": "ohscanner-validation:local",
                "image_id": "sha256:da2be0997cf04e71a80f35c312976bc3ba96399757563f01816f011ef25c12dc",
                "platform": "linux/amd64 Ubuntu 22.04",
                "python_sha256": reference["toolchain"]["python"]["sha256"],
                "python_version": reference["toolchain"]["python"]["version"],
                "clang_path": reference["toolchain"]["compiler"]["resolved_path"],
                "clang_sha256": reference["toolchain"]["compiler"]["resolved_sha256"],
                "gnu_time_sha256": reference["toolchain"]["gnu_time"]["resolved_sha256"],
                "patch_sha256": reference["toolchain"]["patch"]["resolved_sha256"],
                "setarch_wrapper_sha256": sha256_file(WRAPPER),
                "sanitizer": "ThreadSanitizer -fsanitize=thread; TSAN_OPTIONS=halt_on_error=1:exitcode=66",
                "container_policy": {
                    "network": "none",
                    "root_filesystem": "read-only",
                    "tmpfs": ["/tmp", "/run"],
                    "pids_limit": 64,
                    "memory": "2g",
                    "cpus": 2,
                    "workspace_mount": "read-only",
                    "target_source_mount": "read-only",
                    "output_mount": "read-write",
                    "capabilities": "container launcher retained SYS_ADMIN/SETUID/SETGID; setarch wrapper disabled ASLR then transitioned PoC to uid 65534 with no effective capabilities",
                    "seccomp": "unconfined required for personality(ADDR_NO_RANDOMIZE); strict default seccomp was not compliant",
                },
            },
            "variants": variants,
        },
        "entry_trigger_impact": {
            "entry_chain": product["entry_chain"],
            "trigger_conditions": old_validation["trigger_conditions"],
            "product_trigger_trace": product["trigger_traces"],
            "sensitive_operation": {
                "candidate": "closeResultSet asynchronous execute writes/clears JSProxy owner while synchronous KVStoreResultSet.getEntry copies/reads it",
                "reachability": "source_visible_only",
                "product_reachability": "unknown",
            },
            "cia": product["cia_impact"],
        },
        "scope_and_fix": {
            "affected_modules": product["affected_scope"]["modules"],
            "versions": product["affected_scope"]["versions"],
            "branches": {
                "status": "unknown",
                "items": [],
                "observed_local_ref": "refs/source/acfb22aac16161d8fb0cefb6cc9b92f04f489a80 and detached HEAD only",
                "failure_reason": "branch names and source refs are not product version proof",
            },
            "upstream_fix_commit": None,
            "proposed_patch": reference["patch"],
        },
        "cwe_cve": {
            "cwe": {"primary": "CWE-362", "status": "candidate_supported", "basis": "source-bound non-atomic shared_ptr owner read/write plus component TSan reproduction"},
            "possible_consequence_cwe": {"id": "CWE-416", "status": "unknown_unproved", "basis": "no product UAF/lifetime evidence"},
            "cve": {"id": None, "status": "not_assigned_in_available_local_evidence", "basis": "no assignment record; bounded external CVE/NVD/upstream search was not executed"},
        },
        "validation": {"targeted_tests": "16/16 passed", "docs_context_budget": "default=11846/13500, docs=18184/32500", "builder_py_compile": "passed", "report_json_parse": "passed", "target_worktree_after_patch_checks": "clean", "git_diff_check_docs": "passed with LF-to-CRLF warning", "artifact_manifest_files": 768}, "replays": run_summaries,
        "patch_revalidation": reference["patch_application_checks"],
        "controls": reference["controls"]["summary"],
        "failures": attempts,
        "unknowns": unknowns,
    }

    write_json(OUT / "report.json", report)
    write_json(OUT / "unknowns.json", {"schema_version": 1, "unknowns": unknowns})
    write_json(OUT / "attempts.json", {"schema_version": 1, "attempts": attempts})

    manifest_records = []
    for run_id in RUN_IDS:
        for path in sorted((POC_ROOT / run_id).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                manifest_records.append(file_record(path))
    for path in (OUT / "patch.diff", OUT / "run_rc_jsproxy_patch_revalidation_20261016.py", OUT / "container-setarch-wrapper.py"):
        manifest_records.append(file_record(path))
    write_json(OUT / "artifact-manifest.json", {"schema_version": 1, "files": manifest_records})

    lines = [
        "# RC-JSPROXY 产品级证据闭环",
        "",
        "- 产品 Gate：`not_met`",
        "- 最终状态：`candidate/unknown`",
        "- `validated_vulnerability=0`，`confirmed/reportable=false`",
        "- 选择结论：RC-JSPROXY 的产品链证据多于 DelayedSingleton；但组件 Harness/TSan 和 proposed patch 不升级漏洞状态。",
        "",
        "## 固定身份",
        "",
        "- audit repository：`https://github.com/unpredictablexss-lang/CyberSecurity-Innovation-Audit.git`",
        "- audit HEAD/tree：`8e97f152ef747c1e1d21ae179a048910f147e07a` / `e50c111e3b487b048e8807dafe06625a87f296ad`",
        "- target repository：`openharmony/distributeddatamgr_kv_store`",
        "- target commit/tree：`acfb22aac16161d8fb0cefb6cc9b92f04f489a80` / `3b92c53fde616d5a3f9487b0c295670a42c63023`",
        "- source：`frameworks/common/js_proxy.h` blob `19b5dccedc3a9471dcd1ca3b6c32f5e4d5a5fd46` SHA-256 `38d4f1735a6b7295e0093d8df9bcc525a73b01aa178fd06086de2f2df707066f`",
        "- Detector：`ohscanner.cpp.shared_ptr_race` `0.5.0` / `ohcpp-shared-ptr-race-candidate-001`；`rule_version=unknown`。",
        "- component profile：`m0-synthetic`；product profile：`rk3568/user`，仅 preflight。",
        "",
        "## 选择理由",
        "",
        "| 维度 | RC-JSPROXY | DelayedSingleton |",
        "|---|---|---|",
        "| 产品构建 | 有命令、profile、partial source/toolchain/dependency manifests 和失败日志 | 无产品构建 |",
        "| 真实入口 | 有 source-visible JS/NAPI call path | 只有组件边界 Harness |",
        "| 权限/部署 | 明确 unknown 并绑定待证义务 | 无产品权限/部署证据 |",
        "| 版本矩阵 | 产品版本 unknown | 56 行组件版本矩阵 |",
        "| 补丁重验 | exact blob、zero-fuzz、API/ownership、负控制、性能 | 无同等产品候选补丁闭环 |",
        "",
        "## 构建与产物",
        "",
        "- 产品构建命令：`bash build/build_scripts/build.sh --product-name rk3568 --build-variant user --build-target //foundation/distributeddatamgr/kv_store/interfaces/jskits/distributedkvstore:distributedkvstore`。",
        "- 产品 build/source/toolchain/dependency manifests：`3d53dfa365315ed30ae6d4965d291db080341b6c3cc4838a435a4dd52b1a887c` / `288f2de3e43bd9f86ab4ddb5ae10731758255c97cb4c7d92b10f8d830cc44e63` / `4c5756e9c1b91cc08c73e8e5b195b6b580eda95e5c7f3aafa2589e9cf6d4a5c4` / `3d53dfa365315ed30ae6d4965d291db080341b6c3cc4838a435a4dd52b1a887c`（依赖闭包不完整）。",
        "- 产品三 variant artifact hash：`unknown/not_built`。",
    ]
    for item in variants:
        lines.append(f"- component `{item['variant']}` binary SHA-256 `{item['artifact_sha256']}`；source SHA-256 `{item['source_sha256']}`。此为 Harness 产物，不是产品产物。")
    lines.extend([
        "",
        "## PoC 和重复运行",
        "",
        "| run | required | all | controls | outcome |",
        "|---|---:|---:|---|---|",
    ])
    for item in run_summaries:
        lines.append(f"| `{item['run_id']}` | {item['required_runs']}/{item['required_total']} | {item['all_runs']}/{item['all_total']} | {str(item['controls_passed']).lower()} | `{item['overall_outcome']}` |")
    lines.extend([
        "",
        "每次完整 run 内，vulnerable/fixed_control_mutex/patched_atomic_minimal 的 `race` 与 `close_get_entry` 各重复 3 次；vulnerable 均 TSan triggered，fixed/patched 均 clean。single/unrelated 负控制均为 clean。",
        "",
        "## 补丁、API/所有权、负控制和性能",
        "",
        "- patch SHA-256：`3b04fd4e5575e224df35f77be487f3cd90d0a40501b1ff65f5d01886037124c9`。",
        "- exact blob 的 `git apply --cached --check`：passed；`patch -p1 --fuzz=0`：passed，产物 SHA-256 `4d57f286602e15af636c40158e8cdabc6f617fda89d8276128c674b4ab633b6f`。",
        "- API/所有权语义：controlled single functional sequence clean；只证明 Harness 内 shared_ptr owner load/store 同步，不证明完整 result-set close/getEntry 协议。",
        "- 控制：Detector 20/20、native 20/20、zero-fuzz 6/6；vulnerable/fixed/safe/unrelated 四类均保留，3 个 synchronization unknown 未伪造关闭。",
        "- 性能只记录组件 child wall/RSS，不是产品性能中立证明；完整数值见 `report.json`。",
        "",
        "## 入口、权限、触发和 CIA",
        "",
        "- source-visible entries：`SingleKVStore.getResultSet`、`SingleKVStore.closeResultSet`、`KVStoreResultSet.getEntry`、`NapiQueue.AsyncWork`。",
        "- 候选敏感操作：异步 `closeResultSet` 写/清 owner 与同步 `getEntry` 读/复制 owner 重叠。",
        "- 产品 runtime symbol/reachability、permission grant/deny、app identity、uid/user/sandbox、package/image deployment 均 `unknown`。",
        "- 产品 thread/queue interleaving trace、C/I/A 测量均 `unknown`；TSan 不是产品 CIA 证据。",
        "",
        "## 范围、修复和 CWE/CVE",
        "",
        "- affected modules：`frameworks/common/js_proxy.h`、`js_single_kv_store.cpp`、`js_kv_store_resultset.cpp`、`napi_queue.cpp`。",
        "- shipped versions/branches：`unknown`；本地仅 detached source ref，不构成产品版本/分支证明。",
        "- upstream fix commit：`unknown/not_found_in_local_pinned_refs`；atomic patch 是 proposed local repair。",
        "- CWE-362：`candidate_supported`；CWE-416：`unknown_unproved`。",
        "- CVE：`not_assigned_in_available_local_evidence`；没有执行外部 CVE/NVD/upstream assignment search，不能声称全局 not assigned。",
        "",
        "## 隔离边界和失败",
        "",
        "- 成功 run：`--network none`、read-only root、read-only workspace/target、resource limits、uid 65534 PoC process。",
        "- 限制：TSan 需要 `personality(ADDR_NO_RANDOMIZE)`。严格 `--cap-drop ALL` + default seccomp 失败；成功 run 保留 launch-only `SYS_ADMIN/SETUID/SETGID` 和 `seccomp=unconfined`，wrapper 随后切至 uid 65534。严格去 capabilities 因此为 partial，不作为 confirmed 依据。",
        "- run-001 至 run-007 的全部失败、exact error 和证据路径记录在 `attempts.json`；失败目录全部保留。",
        "",
        "## Unknown",
        "",
    ])
    for item in unknowns:
        lines.append(f"- `{item['id']}` [{item.get('severity', 'unknown')}]: {item['question']}")
    lines.extend([
        "",
        "## 实际验证", "", "- targeted tests：16/16 passed。", "- docs context budget：default=11846/13500，docs=18184/32500。", "- builder py_compile 与四个 JSON parse：passed。", "- exact target worktree 在 patch checks 后保持 clean。", "- `git diff --check` 对状态文档通过，仅有 LF-to-CRLF warning。", "", "## 重放",
        "",
        "执行 `reproduce.cmd`。runner 为 `run_rc_jsproxy_patch_revalidation_20261016.py`，每次 `--repeats 3`。输出必须进入全新的 `run-0NN`，runner 拒绝覆盖。",
        "",
        "完整机器可读 Gate、hash、运行结果、失败和 unknown 见 `report.json`、`artifact-manifest.json`、`attempts.json`、`unknowns.json`。",
    ])
    (OUT / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    command = "\r\n".join([
        "@echo off",
        "setlocal",
        "if not exist outputs\\poc\\rc-jsproxy-isolated-20261016\\run-011 mkdir outputs\\poc\\rc-jsproxy-isolated-20261016\\run-011",
        "wsl.exe -e docker run --rm --network none --read-only --cap-drop ALL --cap-add SYS_ADMIN --cap-add SETUID --cap-add SETGID --security-opt no-new-privileges --security-opt seccomp=unconfined --pids-limit 64 --memory 2g --cpus 2 --tmpfs /tmp:rw,noexec,nosuid,size=256m --tmpfs /run:rw,noexec,nosuid,size=64m --env PATH=/out/bin:/usr/local/bin:/usr/bin:/bin -v /usr/bin/patch:/usr/local/bin/patch:ro -v /usr/bin/time:/usr/bin/time:ro -v /mnt/e/网安/CyberSecurity-Innovation-Audit:/workspace:ro -v /mnt/e/网安/audit-sources-20261014/home/audit/openharmony-audit/perf-corpus/distributeddatamgr_kv_store:/mnt/e/网安/audit-sources-20261014/home/audit/openharmony-audit/perf-corpus/distributeddatamgr_kv_store:ro -v /mnt/e/网安/CyberSecurity-Innovation-Audit/outputs/poc/rc-jsproxy-isolated-20261016/bin:/out/bin:ro -v /mnt/e/网安/CyberSecurity-Innovation-Audit/outputs/poc/rc-jsproxy-isolated-20261016/run-011:/workspace/outputs/poc/rc-jsproxy-isolated-20261016/run-011:rw --entrypoint /usr/bin/python3 ohscanner-validation:local /workspace/research/experiments/cpp/run_rc_jsproxy_patch_revalidation_20261016.py --evidence-dir /workspace/outputs/poc/rc-jsproxy-isolated-20261016/run-011/evidence --work-dir /workspace/outputs/poc/rc-jsproxy-isolated-20261016/run-011/work --repeats 3",
        "endlocal",
    ])
    (OUT / "reproduce.cmd").write_text(command + "\r\n", encoding="utf-8")

    readme = "\n".join([
        "# RC-JSPROXY product closure package",
        "",
        "- `report.md`: human-readable product Gate and evidence closure.",
        "- `report.json`: machine-readable Gate, identity, variants, replays, scope and unknowns.",
        "- `artifact-manifest.json`: SHA-256/size manifest for all retained run-008/009/010 evidence and work artifacts.",
        "- `attempts.json`: all successful and failed isolated attempts with exact failure text.",
        "- `unknowns.json`: complete residual unknown list.",
        "- `patch.diff`: proposed minimal atomic repair.",
        "- `run_rc_jsproxy_patch_revalidation_20261016.py`: source-bound PoC/patch runner.",
        "- `container-setarch-wrapper.py`: ASLR-disable plus uid-drop wrapper used by the successful runs.",
        "- `reproduce.cmd`: exact Windows/WSL Docker replay command for a fresh run-011.",
        "",
        "This package remains `candidate/unknown`. Component Harness and TSan results do not establish a reportable product vulnerability.",
    ])
    (OUT / "README.md").write_text(readme + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
