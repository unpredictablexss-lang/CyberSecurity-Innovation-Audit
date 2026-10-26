#!/usr/bin/env python3
"""Verify archived C1 target-build artifacts without promoting profile readiness.

This checks one pinned ARM32 compile edge and its copied evidence files. It does
not inspect the historical replay profiles, rebuild the product, or assert that
the full image/runtime was produced.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[3]
PROFILE = HERE / "profile.json"
TARGET = "arkcompiler/ets_runtime/ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
EXPECTED_COMMIT = "a65a2853ccae13da167d9aa4720ab8b11ec16656"
EXPECTED_TREE = "8781f036a3e7e04d8e0b34970d5f623b42875016"
EXPECTED_TARGET_BLOB = "68fb3b0adc4f9062889a861be51b7be90362e37a"
EXPECTED_TARGET_SHA256 = "76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c"
EXPECTED_OBJECT_SHA256 = "865a1639c3f73f24f7235400228d0bd341930aa903231cd2c4ff21de25f220d5"
EXPECTED_DEPENDENCY_CLOSURE_SHA256 = "042b92b0bfe1db0424124b87f534c78039877e6141cfb8794d8f3b991a70d2af"
SINK_BINDING = ROOT / "research/deliveries/cpp/C_LINE_C1_SINK_BINDING_20261019.json"


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def verify() -> dict:
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    require(profile.get("schema") == "ohscanner.c1.product-gn-profile/v1", "unexpected profile schema")
    require(profile.get("status") == "partial", "profile status must remain partial")

    runtime = profile["source_archive"]["pinned_projects"]["arkcompiler/ets_runtime"]
    target = profile["source_archive"]["critical_files"]["runtime_target"]
    require(runtime.get("commit") == EXPECTED_COMMIT, "runtime commit mismatch")
    require(runtime.get("tree") == EXPECTED_TREE, "runtime tree mismatch")
    require(target.get("path") == TARGET, "target source path mismatch")
    require(target.get("git_blob_oid") == EXPECTED_TARGET_BLOB, "target source Git blob mismatch")
    require(target.get("sha256") == EXPECTED_TARGET_SHA256, "target source SHA-256 mismatch")
    require(target.get("matches_pin") is True, "target source pin is not verified")
    sink = json.loads(SINK_BINDING.read_text(encoding="utf-8"))
    require(sink.get("repository") == "openharmony/arkcompiler_ets_runtime", "sink binding repository mismatch")
    require(sink.get("commit") == EXPECTED_COMMIT and sink.get("resolved_tree") == EXPECTED_TREE,
            "sink binding source profile mismatch")
    bound_rows = {row["path"]: row for row in sink["bindings"]}
    target_row = bound_rows.get("ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp")
    creator_row = bound_rows.get("ecmascript/compiler/new_object_stub_builder.cpp")
    require(target_row and target_row.get("matches") and target_row.get("resolved_blob") == EXPECTED_TARGET_BLOB,
            "source binding manifest does not verify the target blob")
    require(creator_row and creator_row.get("matches"), "source binding manifest does not verify creator source")

    artifacts = profile["generated_artifacts"]
    commands = [row for row in artifacts["target_commands"]
                if row.get("kind") == "product_ohos_arm32"
                and row.get("command_sha256") == "c6d7959215306a67152ac3c2bf1f5012ba919107e27380691c0f9c32e6a6fa88"]
    require(len(commands) == 1, "expected exactly one pinned product ARM32 compile edge")
    command = commands[0]
    require(command.get("target_triple_flags") == ["arm-linux-ohos"], "target triple mismatch")
    require(command.get("file", "").endswith("builtins_typedarray_stub_builder.cpp"), "compile source mismatch")
    require(command.get("command_sha256") == "c6d7959215306a67152ac3c2bf1f5012ba919107e27380691c0f9c32e6a6fa88",
            "compile command digest mismatch")

    run_info = artifacts["target_object_build_run"]
    run_path = HERE / run_info["path"]
    require(digest(run_path) == run_info["sha256"], "target build run artifact hash mismatch")
    run = json.loads(run_path.read_text(encoding="utf-8"))
    require(run.get("target", "").endswith("builtins_typedarray_stub_builder.o"), "built object target mismatch")
    require(run_info.get("target_object_sha256") == EXPECTED_OBJECT_SHA256, "built object hash mismatch")
    overlays = run.get("byte_identical_source_overlays", [])
    require(len(overlays) == 34, "unexpected byte-identical overlay count")
    require(all(row.get("source_sha256") == row.get("overlay_sha256") for row in overlays),
            "an overlay differs from its pinned source bytes")

    closure_info = run_info
    closure_path = HERE / closure_info["dependency_manifest_path"]
    require(digest(closure_path) == closure_info["dependency_manifest_sha256"] == EXPECTED_DEPENDENCY_CLOSURE_SHA256,
            "dependency closure hash mismatch")
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    require(closure.get("dependency_count") == 512 and closure.get("parsed_path_count") == 512,
            "dependency count mismatch")
    require(closure.get("existing_count") == 512 and closure.get("missing_count") == 0,
            "dependency closure has missing paths")
    dependencies = closure.get("dependencies", [])
    require(len(dependencies) == 512 and all(row.get("exists") and row.get("sha256") for row in dependencies),
            "dependency rows are incomplete")
    require(any(row.get("sha256") == EXPECTED_TARGET_SHA256 for row in dependencies),
            "pinned target source is absent from the dependency closure")

    macro_info = artifacts["target_preprocessor_macro_dump"]
    macro_path = HERE / macro_info["path"]
    require(digest(macro_path) == macro_info["sha256"], "preprocessor macro dump hash mismatch")
    macros = macro_path.read_text(encoding="utf-8")
    for line in ("#define NDEBUG 1", "#define PANDA_TARGET_OHOS 1", "#define PANDA_TARGET_ARM32 1"):
        require(line in macros, "required product macro missing: " + line)
    require("#define ENABLE_ASM_ASSERT " not in macros, "ENABLE_ASM_ASSERT must remain undefined in this profile")

    ast_rows = artifacts["target_clang_ast_dumps"]
    require(len(ast_rows) == 3, "expected Filter, creator, and store AST dumps")
    for row in ast_rows:
        ast_path = HERE / row["path"]
        require(digest(ast_path) == row["sha256"], "Clang AST dump hash mismatch: " + row["path"])
        require(row.get("derived_argv_sha256"), "Clang AST command is not bound: " + row["path"])
    ast_observations = profile["execution_attempts"]["target_ast_inspection"]["observations"]
    require(ast_observations.get("Filter") ==
            "void (GateRef, GateRef, GateRef, Variable *, Label *, Label *)", "Filter AST signature mismatch")
    require(ast_observations.get("NewTypedArray", "").startswith("GateRef (GateRef, GateRef, GateRef, GateRef)"),
            "creator overload is not resolved to the expected signature")
    require(ast_observations.get("StoreTypedArrayElement") ==
            "GateRef (GateRef, GateRef, GateRef, GateRef, GateRef)", "store AST signature mismatch")
    require("after its HasPendingException guard" in ast_observations.get("type_flow", ""),
            "resolved type flow does not document exception-guard ordering")

    runtime_info = profile["runtime_behavior"]
    runtime_record_path = HERE / runtime_info["record"]
    require(digest(runtime_record_path) == runtime_info["record_sha256"],
            "runtime behavior record hash mismatch")
    runtime_record = json.loads(runtime_record_path.read_text(encoding="utf-8"))
    perturbation = runtime_record["artifacts"]["species_protector_perturbation"]
    runtime_dir = runtime_record_path.parent
    for artifact_key, file_key in (
        ("source_sha256", "species_protector_perturbation.js"),
        ("abc_sha256", "species_protector_perturbation.abc"),
        ("product_stdout_sha256", "species_protector_perturbation.stdout"),
        ("product_stderr_sha256", "species_protector_perturbation.stderr"),
    ):
        require(digest(runtime_dir / file_key) == perturbation[artifact_key],
                "runtime perturbation artifact hash mismatch: " + file_key)
    require(perturbation.get("product_exit_code") == 0,
            "species protector perturbation did not complete successfully")
    observed = perturbation["same_process_observations"]
    require(observed.get("before_protector_invalidation") ==
            "filter on Int8Array subclass returned Int8Array", "runtime baseline result mismatch")
    require(observed.get("species_getter_calls_after_invalidation") == 1 and
            observed.get("after_protector_invalidation") == "filter returned Uint16Array" and
            observed.get("first_result_value") == 6, "runtime protector perturbation result mismatch")
    callback_probe = runtime_record["artifacts"]["species_callback_mutation_probe"]
    for artifact_key, file_key in (
        ("source_sha256", "species_callback_mutation_probe.js"),
        ("abc_sha256", "species_callback_mutation_probe.abc"),
        ("product_stdout_sha256", "species_callback_mutation_probe.stdout"),
        ("product_stderr_sha256", "species_callback_mutation_probe.stderr"),
    ):
        require(digest(runtime_dir / file_key) == callback_probe[artifact_key],
                "runtime callback-mutation artifact hash mismatch: " + file_key)
    callback_result = callback_probe["observation"]
    require(callback_probe.get("product_exit_code") == 0 and
            callback_result.get("callback_calls") == 2 and
            callback_result.get("species_getter_calls") == 1 and
            callback_result.get("result_type") == "Uint8Array" and
            callback_result.get("result_values") == [120, 121],
            "runtime callback species-mutation result mismatch")
    method_probes = runtime_record["artifacts"]["individual_method_probes"]
    method_markers = {
        "set": "set_no_species_read:pass",
        "copywithin": "copywithin_no_species_read:pass",
        "with": "with_no_species_read_intrinsic_result:pass",
    }
    for method, marker in method_markers.items():
        prefix = "typedarray_" + method + "_no_species_probe"
        probe = method_probes[method]
        for key, suffix in (("source_sha256", ".js"), ("abc_sha256", ".abc"),
                            ("product_stdout_sha256", ".stdout"), ("product_stderr_sha256", ".stderr")):
            require(digest(runtime_dir / (prefix + suffix)) == probe[key],
                    "runtime " + method + " artifact hash mismatch: " + suffix)
        stdout = (runtime_dir / (prefix + ".stdout")).read_text(encoding="utf-8")
        require(probe.get("product_exit_code") == 0 and marker in stdout,
                "runtime " + method + " no-species control did not pass")
    source_cause = runtime_record["runtime_observations"]["protector_perturbation"]
    require(source_cause.get("source_commit") == EXPECTED_COMMIT,
            "runtime cause source commit does not match product profile")
    require(source_cause.get("typed_array_helper_source_sha256") ==
            runtime_record["runtime_observations"]["source_file_sha256"],
            "runtime fast-path source binding mismatch")
    object_operator = (ROOT.parent / "openharmony/arkcompiler/ets_runtime/ecmascript/object_operator.cpp")
    if object_operator.is_file():
        require(digest(object_operator) == source_cause["object_operator_source_sha256"],
                "local pinned object_operator.cpp source digest mismatch")

    return {
        "status": "verified_scoped_artifacts_profile_remains_partial",
        "commit": EXPECTED_COMMIT,
        "tree": EXPECTED_TREE,
        "target_blob": EXPECTED_TARGET_BLOB,
        "creator_source_blob": creator_row["resolved_blob"],
        "compile_edge": command["kind"],
        "object_sha256": EXPECTED_OBJECT_SHA256,
        "dependency_count": len(dependencies),
        "macro_dump_sha256": macro_info["sha256"],
        "ast_dump_count": len(ast_rows),
        "species_protector_perturbation": "verified_same_process_guard_switch",
        "species_callback_mutation": "verified_result_creation_observes_callback_change",
        "isolated_typedarray_methods": {name: "verified_safe_control" for name in method_markers},
        "product_image_or_runtime": "not_verified",
        "historical_profile_transfer": "not_allowed",
    }


def main() -> int:
    try:
        result = verify()
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        print("BLOCKED:", error, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
