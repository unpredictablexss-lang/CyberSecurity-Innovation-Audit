#!/usr/bin/env python3
"""Bind the 2026-10-19 C1 GN/preprocessor observations into C4."""
from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path


HERE = Path(__file__).resolve().parent
PROJECT = HERE.parents[3]
WORKSPACE = HERE.parents[4]
C1_REL = Path("research/experiments/ark_runtime/c1_20261017")
PROFILE_PATH = PROJECT / "research/experiments/ark_runtime/c1_20261017/product_profile_20261019.v1.json"
MANIFEST_PATH = HERE / "exact_snapshot_manifest.v1.json"
BINDING_PATH = HERE / "report_binding.v1.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def workspace_rel(path: Path) -> str:
    return path.relative_to(WORKSPACE).as_posix()


def main() -> int:
    profile = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
    arm_actions = [
        action
        for action in profile["runs"][1]["target_source_actions"]
        if action["target"] == "arm-linux-ohos"
    ]
    if len(arm_actions) != 2:
        raise SystemExit(f"expected 2 ARM actions, got {len(arm_actions)}")

    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    new_files = [
        ("c1-product-profile", "C1 exact-manifest product GN profile evidence", PROFILE_PATH),
        ("c1-product-args-gn", "C1 exact product evaluated GN arguments", PROJECT / C1_REL / "product_args_20261019.args.gn"),
        ("c1-product-replay-log", "C1 repeated product GN generation transcript", PROJECT / C1_REL / "hb_probe_20261019_replay2.log"),
        ("c1-preprocessor-observation", "C1 exact compile action preprocessing attempt", PROJECT / C1_REL / "preprocessor_attempt_20261019/preprocessor_observation.json"),
        ("c1-ninja-graph-failure", "C1 generated Ninja graph parse diagnostic", PROJECT / C1_REL / "preprocessor_attempt_20261019/ninja_query.log"),
        ("c1-preprocessor-success-readme", "C1 successful exact-profile preprocessing handoff", PROJECT / C1_REL / "preprocessor_success_20261019/README.md"),
        ("c1-preprocessor-success-manifest", "C1 successful preprocessing evidence manifest", PROJECT / C1_REL / "preprocessor_success_20261019/evidence_manifest.v1.json"),
        ("c1-preprocessor-success-observation", "C1 successful exact ARM action preprocessing observation", PROJECT / C1_REL / "preprocessor_success_20261019/results/preprocessor_observation.json"),
        ("c1-direct-object-compile-driver", "C1 direct exact-profile Clang compile driver; supplemental unisolated execution", PROJECT / C1_REL / "run_profile_object_compile_20261019.py"),
        ("c1-object-compile-supplement-readme", "C1 supplemental direct object compile evidence and isolation limits", PROJECT / C1_REL / "preprocessor_success_20261019/object_compile_supplement_20261019/README.md"),
        ("c1-object-compile-supplement-observation", "C1 direct Clang object compile observations for both selected ARM actions", PROJECT / C1_REL / "preprocessor_success_20261019/object_compile_supplement_20261019/object_compile_observation.v1.json"),
        ("c1-isolated-ninja-build-observation", "C1 exact-profile Ninja target attempt in no-network namespace; blocked before target compile", PROJECT / C1_REL / "ninja_isolated_build_20261019/observation.v1.json"),
        ("c1-isolated-ninja-build-runner", "C1 user/mount/network namespace runner with read-only source/toolchain and writable GN output", PROJECT / C1_REL / "run_ninja_targets_isolated_20261019.sh"),
        ("c1-isolated-ninja-observation-capture", "C1 read-only hash and result capture for the isolated Ninja attempt", PROJECT / C1_REL / "capture_ninja_isolated_build_observation.py"),
        ("c1-isolated-ninja-boundary", "C1 observed namespace and mount boundary for the failed Ninja target attempt", PROJECT / C1_REL / "ninja_isolated_build_20261019/attempt2/execution_boundary.txt"),
        ("c1-isolated-ninja-target1-log", "C1 exact Ninja target-1 failure log, including duplicate-output warnings", PROJECT / C1_REL / "ninja_isolated_build_20261019/attempt2/target-1.log"),
        ("c1-isolated-ninja-target1-status", "C1 exact Ninja target-1 return code and target identity", PROJECT / C1_REL / "ninja_isolated_build_20261019/attempt2/target-1.status"),
        ("c1-isolated-ninja-target-query", "C1 Ninja query for exact target object and order-only inputdeps stamp", PROJECT / C1_REL / "ninja_isolated_build_20261019/attempt2/query-target-1.log"),
        ("c1-isolated-ninja-stamp-query", "C1 Ninja query showing the transitive inputdeps stamp prerequisites", PROJECT / C1_REL / "ninja_isolated_build_20261019/attempt2/query-stamp.log"),
        ("c1-cow-ninja-build-observation", "C1 exact-profile Ninja object builds under read-only root and source COW", PROJECT / C1_REL / "ninja_cow_target_build_20261019/observation.v1.json"),
        ("c1-cow-source-upper-manifest", "C1 source COW upper-layer content inventory and lower comparisons", PROJECT / C1_REL / "ninja_cow_target_build_20261019/source_upper.v1.json"),
        ("c1-host-ruby-runtime-profile", "C1 hash-pinned Ruby 3.2.3 host generator runtime", PROJECT / C1_REL / "ninja_cow_target_build_20261019/ruby_runtime.v1.json"),
        ("c1-cow-root-readonly-runner", "C1 exact Ninja target runner with read-only root/source lower and COW source overlay", PROJECT / C1_REL / "run_ninja_targets_cow_ro_root_20261019.sh"),
        ("c1-cow-target-capture-script", "C1 reproducible capture of target logs, objects, profile commands, and COW changes", PROJECT / C1_REL / "capture_ninja_cow_target_build_20261019.py"),
        ("c1-cow-target-build-verifier", "C1 read-only verifier for root-readonly Ninja object build evidence", PROJECT / C1_REL / "verify_ninja_cow_target_build_20261019.py"),
        ("c1-snapshot-materialization-audit", "C1 audit of manifest project archives, nested gitlink content, and exact linkfile sources", PROJECT / C1_REL / "snapshot_gitlink_linkfile_audit_20261019.json"),
        ("c1-snapshot-materialization-audit-script", "C1 reproducible exact gitlink directory and manifest linkfile source audit", PROJECT / C1_REL / "audit_snapshot_gitlink_linkfile_20261019.py"),
        ("c1-materialization-report", "C1 captured external manifest archive materialization report", PROJECT / C1_REL / "materialization_manifest_20261019.json"),
        ("c1-nested-gitlink-origins", "C1 read-only mapping of nested gitlink commits to parent .gitmodules URLs", PROJECT / C1_REL / "nested_gitlink_origins_20261019.json"),
        ("c1-nested-gitlink-origins-script", "C1 reproducible nested gitlink origin inventory", PROJECT / C1_REL / "audit_nested_gitlink_origins_20261019.py"),
        ("c1-cow-execution-boundary", "C1 observed read-only-root namespace and writable GN/evidence mount boundary", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt7/execution_boundary.txt"),
        ("c1-cow-prerequisite-runner", "C1 incremental prerequisite-closure COW Ninja runner, preceding root-read-only replay", PROJECT / C1_REL / "run_ninja_targets_cow_fullenv_20261019.sh"),
        ("c1-cow-prerequisite-boundary", "C1 attempt 6 user/mount/network namespace and COW mount boundary", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt6/execution_boundary.txt"),
        ("c1-cow-prerequisite-upper", "C1 attempt 6 source-overlay upper-layer inventory", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt6/source_upper.v1.json"),
        ("c1-cow-prerequisite-target1-log", "C1 attempt 6 completed ARM target 1 prerequisite closure and target build", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt6/target-1.log"),
        ("c1-cow-prerequisite-target1-status", "C1 attempt 6 target 1 return code and target identity", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt6/target-1.status"),
        ("c1-cow-prerequisite-target2-log", "C1 attempt 6 completed ARM target 2 prerequisite closure and target build", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt6/target-2.log"),
        ("c1-cow-prerequisite-target2-status", "C1 attempt 6 target 2 return code and target identity", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt6/target-2.status"),
        ("c1-cow-target1-log", "C1 target 1 successful Ninja log under read-only root", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt7/target-1.log"),
        ("c1-cow-target1-status", "C1 target 1 Ninja return code and target identity", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt7/target-1.status"),
        ("c1-cow-target2-log", "C1 target 2 successful Ninja log under read-only root", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt7/target-2.log"),
        ("c1-cow-target2-status", "C1 target 2 Ninja return code and target identity", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt7/target-2.status"),
        ("c1-cow-target1-object", "C1 target 1 Ninja-built ARM object output", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt7/objects/target-1.o"),
        ("c1-cow-target2-object", "C1 target 2 Ninja-built ARM object output", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt7/objects/target-2.o"),
        ("c1-cow-target1-command", "C1 target 1 Ninja graph command matched to exact profile argv", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt7/commands/target-1.command.txt"),
        ("c1-cow-target2-command", "C1 target 2 Ninja graph command matched to exact profile argv", PROJECT / C1_REL / "ninja_cow_target_build_20261019/attempt7/commands/target-2.command.txt"),
        ("c1-ruby-runtime-package", "C1 hash-verified Ubuntu Noble Ruby runtime package", PROJECT / C1_REL / "ninja_cow_target_build_20261019/ruby_packages/ruby3.2_3.2.3-1ubuntu0.24.04.8_amd64.deb"),
        ("c1-libruby-runtime-package", "C1 hash-verified Ubuntu Noble libruby runtime package", PROJECT / C1_REL / "ninja_cow_target_build_20261019/ruby_packages/libruby3.2_3.2.3-1ubuntu0.24.04.8_amd64.deb"),
        ("c2-profile-context-triage", "C2 exact new-profile action-context triage matrix; semantics remain unknown", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/triage_matrix.json"),
        ("c2-profile-context-readme", "C2 profile-context scope and remaining proof requirements", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/README.md"),
        ("c2-object-verification", "C2 recomputed old/new object identities, diffs, and new-profile context evidence", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/object_verification.json"),
        ("c2-source-diffs", "C2 exact function-context patch for the 18 changed dependencies", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/source-diffs.patch"),
        ("c2-new-profile-product-action-census", "C2 new-profile ARM compile actions for changed non-target translation units", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/new_profile_product_action_census_20261019.json"),
        ("c2-product-action-census-capture-script", "C2 streaming compile database census and hash verifier", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/capture_new_profile_product_action_census.py"),
        ("c2-evidence-verifier", "C2 object identity, profile context, and action census verifier", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/verify_c2_evidence.py"),
        ("c2-historical-profile-audit", "C2 bounded old-revision historical manifest candidate audit", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/historical_profile_candidate_audit_20261019.json"),
        ("c2-historical-profile-audit-script", "C2 reproducible bounded manifest ref and old Ark pin audit", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/audit_old_revision_manifest_candidates.py"),
        ("c2-full-manifest-history-audit", "C2 all advertised GitCode manifest refs and reachable history old Ark pin audit", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/full_manifest_history_audit_20261019.json"),
        ("c2-full-manifest-history-audit-script", "C2 reproducible complete advertised-ref history audit", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/audit_full_manifest_history.py"),
        ("c2-all-old-ark-pin-audit", "C2 full advertised manifest history search for every old Ark commit in the dependency matrix", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/all_old_ark_manifest_pins_20261019.json"),
        ("c2-all-old-ark-pin-audit-script", "C2 reproducible full manifest history search for all old Ark commits", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/audit_all_old_ark_manifest_pins_20261019.py"),
        ("c2-full-manifest-support-refs", "C2 full manifest history audit supporting capture: manifest_advertised_refs_full_20261019.txt", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/manifest_advertised_refs_full_20261019.txt"),
        ("c2-full-manifest-support-graph", "C2 full manifest history audit supporting capture: manifest_commit_graph_full_20261019.txt", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/manifest_commit_graph_full_20261019.txt"),
        ("c2-full-manifest-support-refs", "C2 full manifest history audit supporting capture: manifest_local_refs_full_20261019.txt", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/manifest_local_refs_full_20261019.txt"),
        ("c2-full-manifest-support-fsck", "C2 full manifest history audit supporting capture: manifest_mirror_fsck_20261019.log", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/manifest_mirror_fsck_20261019.log"),
        ("c2-full-manifest-support-ark", "C2 full manifest history audit supporting capture: manifest_old_ark_pin_history_matches_20261019.txt", WORKSPACE / "CyberSecurity-Innovation-Audit-c4/research/experiments/ark_runtime/c2_drift_triage_20261018/manifest_old_ark_pin_history_matches_20261019.txt"),
        ("c4-active-include-closure", "C4 hash-bound active dependency closure and direct Ninja producer evidence", HERE / "active_include_closure_20261019.bound.json"),
        ("c4-active-include-capture-script", "C4 read-only active include closure capture implementation", HERE / "capture_active_include_closure.py"),
        ("c4-active-producer-binding-script", "C4 read-only direct Ninja producer binding implementation", HERE / "bind_active_closure_producers.py"),
        ("c4-musl-uapi-side-effect-binding-script", "C4 verification of Musl UAPI directory and stamp side-effect producers", HERE / "bind_musl_uapi_side_effects.py"),
        ("c4-generated-input-graph-closure", "C4 recursive producer-input graph and pinned-source blob closure", HERE / "generated_input_graph_closure_20261019.json"),
        ("c4-generated-input-closure-capture-script", "C4 read-only recursive Ninja input closure capture and verifier", HERE / "capture_generated_input_graph_closure.py"),
    ]
    success = PROJECT / C1_REL / "preprocessor_success_20261019"
    for path in sorted((success / "results").glob("ark-runtime-arm-action-*.d")):
        new_files.append(("c1-success-deps-" + path.stem, "C1 compiler dependency scan output", path))
    for path in sorted((success / "results").glob("ark-runtime-arm-action-*.macros")):
        new_files.append(("c1-success-macros-" + path.stem, "C1 compiler-expanded macro output", path))
    for path in sorted((success / "results").glob("ark-runtime-arm-action-*.ii")):
        new_files.append(("c1-success-preprocessed-" + path.stem, "C1 preprocessed translation unit", path))
    for path in sorted((success / "generated").rglob("*")):
        if path.is_file():
            relative = path.relative_to(success).as_posix()
            new_files.append(("c1-generated-" + hashlib.sha256(relative.encode()).hexdigest()[:16], "C1 GN-generated header output", path))
    object_evidence = success / "object_compile_supplement_20261019"
    for path in sorted(object_evidence.glob("ark-runtime-arm-action-*.o")):
        new_files.append(("c1-object-" + path.stem, "C1 supplemental direct Clang object output; execution was outside original isolation boundary", path))
    for path in sorted(object_evidence.glob("ark-runtime-arm-action-*.d")):
        new_files.append(("c1-object-deps-" + path.stem, "C1 supplemental direct Clang dependency output", path))
    for path in sorted(object_evidence.glob("ark-runtime-arm-action-*.stderr")):
        new_files.append(("c1-object-stderr-" + path.stem, "C1 supplemental direct Clang stderr", path))
    entries = {entry["id"]: entry for entry in manifest["inputs"]}
    for input_id, kind, path in new_files:
        rel = workspace_rel(path)
        content = path.read_bytes()
        entries[input_id] = {
            "id": input_id,
            "kind": kind,
            "workspace_path": rel,
            "bytes": len(content),
            "content_sha256": hashlib.sha256(content).hexdigest(),
            "source": {
                "kind": "workspace_evidence",
                "uri": rel,
                "verification": "sha256_bound_local_evidence",
            },
        }
    manifest["inputs"] = [entries[key] for key in sorted(entries)]

    p = manifest["profile"]
    p["accepted_c1_profile"] = "partial hihope/rk3568 GN compile profile; both ARM actions preprocess and direct supplemental Clang compile successfully"
    p["c1_profile_evidence"] = workspace_rel(PROFILE_PATH)
    p["c1_profile_status"] = (
        "partial: HB GN generation and compile database repeated byte-identically twice; both ARM actions pass "
        "preprocess, dependency scan, and macro dump in isolation and direct supplemental Clang object compile; "
        "the object compile was outside the original container/read-only source boundary; duplicate-output warnings "
        "and incomplete full-snapshot materialization remain"
    )
    p["build_profile"] = (
        "hihope/rk3568; normalized GN profile digest "
        "e86461191c065e3e140afb734c9d8c27818851ae51651f9ba004231fa7d52063; both ARM actions preprocess in isolation and compile supplemental objects outside that boundary"
    )
    p["product_manifest_locked"] = True
    p["target_platform"] = (
        "arm-linux-ohos; ARMv7-A, softfp, NEON, thumb; product vendor/hihope/rk3568; "
        "generated device_path device/board/rockchip/rk3568"
    )
    p["macros"]["definitions"] = arm_actions[0]["definitions_ordered"]
    p["macros"]["status"] = (
        "ordered command-line definitions and compiler-expanded macro dumps captured for both ARM actions; see C1 successful preprocessing evidence"
    )
    p["macros"]["by_action"] = [
        {
            "object_output": action["object_output"],
            "definitions_ordered": action["definitions_ordered"],
            "command_sha256": action["command_sha256"],
        }
        for action in arm_actions
    ]
    p["include_search_paths"]["ordered_paths"] = arm_actions[0]["include_paths_ordered"]
    p["include_search_paths"]["status"] = (
        "ordered compile-command paths and active dependency files captured for both ARM actions; compiler preprocessing completed successfully"
    )
    p["include_search_paths"]["by_action"] = [
        {
            "object_output": action["object_output"],
            "include_paths_ordered": action["include_paths_ordered"],
            "command_sha256": action["command_sha256"],
        }
        for action in arm_actions
    ]
    p["tools"]["preprocessor"] = "OHOS Clang 15.0.4 preprocessor; both selected ARM actions completed preprocess, dependency scan, and macro dump"
    p["tools"]["compiler"] = "OHOS Clang 15.0.4 (02fbe8daf56b9704358bc2e7bea9da79938a7abf)"
    p["tools"]["tool_binary_hashes"] = {
        "python3.12": "02e619087c33f723f4bd8e7f7443f35d87d4383d9592de04b66a3c05a5d4f316",
        "gn": "aa76f11ec5ab820695fdd0973d644d205305b1a23fabcc43e230871f502230a7",
        "ninja": "2c867ca18771ff64d2a9f72f16316760651c98b1fbce692b0542f25de49b112b",
        "clang++": "2b28a71dbd71e1bc7f2b9b793f4add7499bee5d533e2d581df2bd0f716e7011c",
    }
    p["c1_compile_database_status"] = (
        "present: 234245 entries; target source has five actions including two ARM OHOS actions; "
        "full database is byte-identical across two GN runs"
    )
    p["c1_build_profile_digest"] = profile["profile_digest_sha256"]
    p["c1_dependency_policy"] = (
        "Exact GN compile commands, tool hashes, active dependency files, preprocessed outputs, macro dumps, and object outputs "
        "are captured for both selected ARM actions. Supplemental direct Clang compilation succeeded outside the original "
        "container/read-only source boundary; no Ninja target object build or product image build was run."
    )

    reasons = {
        "C1_PRODUCT_BUILD_PROFILE": (
            "A repeatable hihope/rk3568 HB GN profile and successful preprocessing/dependency/macro captures now exist "
            "for both selected ARM actions; supplemental direct Clang object compilation succeeded outside the original "
            "container boundary, but no in-boundary Ninja target object or product image build was run. Ninja reports duplicate-output "
            "warnings and the top-level source export still has 19 unresolved gitlinks plus a missing manifest linkfile source."
        ),
        "GENERATED_BUILD_INPUTS": (
            "The two active -M outputs contain 69 generated/output dependencies. Direct Ninja edges bind 57, while "
            "12 Musl UAPI headers are declared action side effects and are byte-identical to manifest-pinned source "
            "blobs recorded in the action stamp or directory-copy edge. The recursive graph capture binds 1,935 "
            "producer outputs and 1,828 terminal source inputs to pinned Git blobs."
        ),
    }
    closure_path = HERE / "generated_input_graph_closure_20261019.json"
    active_closure_path = HERE / "active_include_closure_20261019.bound.json"
    closure = json.loads(closure_path.read_text(encoding="utf-8")) if closure_path.is_file() else {}
    active_closure = json.loads(active_closure_path.read_text(encoding="utf-8")) if active_closure_path.is_file() else {}
    closure_ref = active_closure.get("producer_graph", {}).get("recursive_input_closure", {})
    generated_inputs_verified = (
        closure.get("status") == "verified_declared_generated_input_graph_closure"
        and closure.get("terminal_input_origin_status_counts") == {"verified_pinned_git_blob": 1828}
        and closure.get("recursive_producer_output_count") == 1935
        and active_closure.get("status") == "verified_active_generated_input_closure"
        and closure_ref.get("sha256") == sha256(closure_path)
    )
    resolved_now = {"ACTUAL_INCLUDE_CLOSURE", "INCLUDE_COMPILER_RESOLUTION", "MACRO_CONFIGURATION", "PREPROCESSOR_TOOLCHAIN"}
    if generated_inputs_verified:
        resolved_now.add("GENERATED_BUILD_INPUTS")
    manifest["unresolved"] = [
        gate for gate in manifest["unresolved"] if gate["id"] not in (resolved_now | {"TARGET_PLATFORM"})
    ]
    for gate in manifest["unresolved"]:
        if gate["id"] in reasons:
            gate["reason"] = reasons[gate["id"]]

    probe = manifest["product_build_probe"]
    probe["execution_state"] = (
        "completed_hb_gn_generation_twice_byte_identical; compile_database_exported; both_arm_actions_preprocessed_dependency_scanned_and_macro_dumped; "
        "ninja_invocations_used_dupbuild_warn_with_duplicate_output_warnings; supplemental_direct_object_compile_succeeded_outside_isolation; no_in_boundary_ninja_target_object_or_product_image_build"
    )
    probe["output_path"] = "/home/deepsleep/c-line-c1-profile-20261018/out-gn-20261019-retry3/rk3568"
    probe["probe_log"] = workspace_rel(PROJECT / C1_REL / "hb_probe_20261019_replay2.log")
    probe["probe_log_sha256"] = sha256(PROJECT / C1_REL / "hb_probe_20261019_replay2.log")
    probe["observed_result"] = (
        "two HB invocations exit 0; normalized args.gn digest stable; compile_commands.json and build.ninja "
        "byte-identical; 234245 compile actions exported; both ARM actions pass preprocess, -M, and -dM -E "
        "after declared generated headers; supplemental direct Clang object compile succeeded outside original isolation; duplicate-output warnings persist; no in-boundary Ninja object or product image build"
    )
    probe["profile_json_path"] = workspace_rel(PROFILE_PATH)
    probe["profile_json_sha256"] = sha256(PROFILE_PATH)
    probe["compile_commands_sha256"] = "f4ac150e2af2d2d0eff5da063e5be3beee973c459d998c50ca119530019cee7e"
    probe["compile_commands_bytes"] = 4103004071
    probe["build_ninja_sha256"] = "eb313a6a3f282c71c72186e6f3e2022973e6fa0d07efc18426e7505ce7fc8951"
    probe["preprocessing_observation_path"] = workspace_rel(
        PROJECT / C1_REL / "preprocessor_attempt_20261019/preprocessor_observation.json"
    )
    probe["preprocessing_observation_sha256"] = sha256(
        PROJECT / C1_REL / "preprocessor_attempt_20261019/preprocessor_observation.json"
    )
    probe["preprocessing_success_observation_path"] = workspace_rel(success / "results/preprocessor_observation.json")
    probe["preprocessing_success_observation_sha256"] = sha256(success / "results/preprocessor_observation.json")

    spec = importlib.util.spec_from_file_location("dependency_manifest", HERE / "dependency_manifest.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    manifest["summary_sha256"] = module.calculate_summary(manifest)
    MANIFEST_PATH.write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

    binding = json.loads(BINDING_PATH.read_text(encoding="utf-8"))
    binding["dependency_reference"]["dependency_summary_sha256"] = manifest["summary_sha256"]
    binding["dependency_reference"]["verification_status"] = "blocked"
    BINDING_PATH.write_text(json.dumps(binding, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({
        "manifest": str(MANIFEST_PATH),
        "summary_sha256": manifest["summary_sha256"],
        "input_count": len(manifest["inputs"]),
        "unresolved_count": len(manifest["unresolved"]),
        "removed_gate": "TARGET_PLATFORM",
        "status": "blocked",
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
