#!/usr/bin/env python3
"""Audit historical GN source bindings versus unresolved generated build args."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
OUTPUT = ROOT / "research/deliveries/cpp/C_LINE_HISTORICAL_GN_BUILD_PROFILE_AUDIT_20261019.json"
GIT_DIR = "/mnt/d/openHarmonyScanner/openharmony/.repo/projects/arkcompiler/ets_runtime.git"
PROFILES = (
    ("parent", "830e85b40240677039719fcbf14f721ad3b19050", "579712c1ebbb703d17cea422b1572023bed5d8a4"),
    ("fix", "a0e30483ab3e4aead67ecfb5c708489915e447f9", "82af11ced4297818410ccf61906b703d25b69165"),
)
PATHS = ("ecmascript/compiler/BUILD.gn", "BUILD.gn")
LOCAL_PROFILE_RELATIVE = Path(
    "outputs/ark-runtime-isolated-validation-20261018/openharmony-5.0.2"
)
sys.path.insert(0, str(ROOT))
from research.full_scan_20261018.lanes.c.model import RuntimeTypeModel  # noqa: E402


def git(*args: str) -> bytes:
    proc = subprocess.run(["wsl.exe", "-d", "Ubuntu", "--", "git", "-C", GIT_DIR, *args],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    if proc.returncode:
        raise RuntimeError(proc.stderr.decode("utf-8", "replace").strip())
    return proc.stdout


def main() -> int:
    model = RuntimeTypeModel()
    records = []
    for role, commit, expected_tree in PROFILES:
        tree = git("rev-parse", f"{commit}^{{tree}}").decode("ascii").strip()
        if tree != expected_tree:
            raise ValueError(f"{role} tree mismatch: {tree}")
        files = []
        for path in PATHS:
            data = git("show", f"{commit}:{path}")
            oid = git("rev-parse", f"{commit}:{path}").decode("ascii").strip()
            expected = ("bff0145a50065bad462beb5a1feb567ae1aea517" if path == PATHS[0]
                        else "83207ac7903f020ffac2b57b9b184dbd00ce722c")
            if oid != expected:
                raise ValueError(f"{role} {path} Git blob mismatch: {oid}")
            text = data.decode("utf-8")
            files.append({
                "path": path,
                "git_blob_oid": oid,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
                "model_dependency_binding": any(dep_path == path and dep_oid == oid
                                                 for dep_path, dep_oid in model.additional_source_dependencies),
            })
            if path == PATHS[0]:
                lines = text.splitlines()
                references = [
                    {"line": n, "text": lines[n - 1].strip()}
                    for n in range(1, len(lines) + 1)
                    if '"$js_root:ark_jsruntime_compiler_config"' in lines[n - 1]
                    or '"$js_root:ark_jsruntime_public_config"' in lines[n - 1]
                ]
            else:
                lines = text.splitlines()
                names = ("config(\"ark_jsruntime_public_config\")", "config(\"ark_jsruntime_compiler_config\")",
                         "config(\"ark_jsruntime_common_config\")", "if (build_variant == \"user\")",
                         "} else if (is_debug) {", "if (enable_asm_assert) {", "if (run_with_asan) {")
                config_lines = []
                for n, line in enumerate(lines, 1):
                    if any(marker in line for marker in names):
                        config_lines.append({"line": n, "text": line.strip()})
        records.append({"role": role, "commit": commit, "tree": tree, "files": files,
                        "config_references": references, "root_config_conditions": config_lines})
    # A generated GN profile exists in the shared workspace, but its runtime
    # checkout must be fingerprinted before anyone transfers its macros to the
    # exact parent/fix replay pair.
    local_profile = ROOT.parent / LOCAL_PROFILE_RELATIVE
    local_runtime = local_profile / "arkcompiler/ets_runtime"
    local_args = local_profile / "out/rk3568/args.gn"
    local_commit = subprocess.run(
        ["wsl.exe", "-d", "Ubuntu", "--", "git", "-C",
         "/mnt/d/openHarmonyScanner/outputs/ark-runtime-isolated-validation-20261018/openharmony-5.0.2/arkcompiler/ets_runtime",
         "rev-parse", "HEAD"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    if local_commit.returncode or not local_args.is_file():
        raise RuntimeError("discovered local generated GN profile is unavailable")
    local_commit_oid = local_commit.stdout.decode("ascii").strip()
    local_tree = subprocess.run(
        ["wsl.exe", "-d", "Ubuntu", "--", "git", "-C",
         "/mnt/d/openHarmonyScanner/outputs/ark-runtime-isolated-validation-20261018/openharmony-5.0.2/arkcompiler/ets_runtime",
         "rev-parse", "HEAD^{tree}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False,
    )
    if local_tree.returncode:
        raise RuntimeError("cannot resolve local profile runtime tree")
    local_args_bytes = local_args.read_bytes()
    local_args_text = local_args_bytes.decode("utf-8")
    selected_args = {}
    for key in ("product_name", "target_cpu", "build_variant", "is_debug", "is_asan", "runtime_mode"):
        for line in local_args_text.splitlines():
            if line.strip().startswith(key + " ="):
                selected_args[key] = line.split("=", 1)[1].strip()
                break
    def local_object(path: str):
        proc = subprocess.run(
            ["wsl.exe", "-d", "Ubuntu", "--", "git", "-C",
             "/mnt/d/openHarmonyScanner/outputs/ark-runtime-isolated-validation-20261018/openharmony-5.0.2/arkcompiler/ets_runtime",
             "rev-parse", f"{local_commit_oid}:{path}"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
        )
        return proc.stdout.decode("ascii").strip() if proc.returncode == 0 else None

    local_profile_record = {
        "path": str(LOCAL_PROFILE_RELATIVE / "out/rk3568/args.gn").replace("\\", "/"),
        "args_sha256": hashlib.sha256(local_args_bytes).hexdigest(),
        "runtime_commit": local_commit_oid,
        "runtime_tree": local_tree.stdout.decode("ascii").strip(),
        "target_blob_at_modeled_path": local_object("ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"),
        "creator_blob_at_modeled_path": local_object("ecmascript/compiler/new_object_stub_builder.cpp"),
        "selected_args": selected_args,
        "matches_parent_or_fix_commit": any(local_commit_oid == commit for _, commit, _ in PROFILES),
        "usable_for_parent_fix_profile": False,
        "reason": "Generated args.gn belongs to a different runtime commit and source blobs; it cannot resolve the pinned parent/fix build profiles.",
    }
    manifest_records = []
    for name in ("openharmony-manifest-20261018.xml", "openharmony-manifest-fixed.xml"):
        path = ROOT.parent / name
        if not path.is_file():
            manifest_records.append({"path": name, "available": False})
            continue
        root = ET.parse(path).getroot()
        projects = [item for item in root.findall("project")
                    if item.get("name") == "arkcompiler_ets_runtime"]
        manifest_records.append({
            "path": name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "runtime_project_revisions": [item.get("revision") for item in projects],
            "matches_parent_or_fix": any(item.get("revision") == commit
                                         for item in projects
                                         for _, commit, _ in PROFILES),
        })
    manifest_history = []
    for root_name, git_dir in (
        ("openharmony", "/mnt/d/openHarmonyScanner/openharmony/.repo/manifests.git"),
        ("openharmony-5.0.2", "/mnt/d/openHarmonyScanner/outputs/ark-runtime-isolated-validation-20261018/openharmony-5.0.2/.repo/manifests.git"),
    ):
        count_proc = subprocess.run(
            ["wsl.exe", "-d", "Ubuntu", "--", "git", "--git-dir=" + git_dir,
             "rev-list", "--all", "--count"], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, check=False,
        )
        if count_proc.returncode:
            raise RuntimeError("cannot count local manifest history for " + root_name)
        commit_searches = []
        for _, commit, _ in PROFILES:
            search = subprocess.run(
                ["wsl.exe", "-d", "Ubuntu", "--", "git", "--git-dir=" + git_dir,
                 "log", "--all", "-S" + commit, "--format=%H", "--", "*.xml"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False,
            )
            if search.returncode:
                raise RuntimeError("cannot search local manifest history for " + commit)
            commit_hits = search.stdout.decode("ascii").splitlines()
            commit_searches.append({"runtime_commit": commit, "manifest_change_commits": commit_hits})
        manifest_history.append({
            "workspace_profile": root_name,
            "manifest_git_dir": git_dir,
            "reachable_manifest_commit_count": int(count_proc.stdout.decode("ascii").strip()),
            "search": "git log --all -S<runtime_commit> --format=%H -- '*.xml'",
            "runtime_commit_searches": commit_searches,
        })
    result = {
        "schema": "c-line-historical-gn-build-profile-audit-v1",
        "repository": "openharmony/arkcompiler_ets_runtime",
        "profiles": records,
        "discovered_nonmatching_local_profile": local_profile_record,
        "local_build_artifact_search": {
            "workspace_root": "D:/openHarmonyScanner",
            "args_gn_matches": [local_profile_record["path"]],
            "compile_commands_json_matches": [],
            "manifest_snapshots": manifest_records,
            "manifest_history_search": manifest_history,
            "interpretation": "The only discovered args.gn belongs to a different runtime commit. No compile_commands.json was found in the workspace search; this does not establish the parent/fix compile commands.",
        },
        "model_assumption": model.build_profile,
        "finding": "Both exact source profiles bind the compiler BUILD.gn blob, which references compiler/public configs defined in the root BUILD.gn. The root BUILD.gn blob is identical in parent and fix but is not a declared RuntimeTypeModel source dependency. It selects NDEBUG and compiler flags based on build_variant/is_debug and gates ENABLE_ASM_ASSERT/RUN_WITH_ASAN on GN args. The only discovered local args.gn belongs to a different runtime commit and different target/creator blobs; historical parent/fix GN args, target toolchain, and resolved compile commands remain unavailable. The model's build_profile is therefore an assumption, not a verified historical product profile.",
        "required_follow_up": [
            "Bind root BUILD.gn and any product/board GN inputs that affect the target compile edge.",
            "Obtain parent and fix generated args.gn and resolved compile commands independently; do not copy current-a65 or the discovered nonmatching local profile.",
            "Keep historical replay and public Runner admission partial/blocked until those values are resolved."
        ],
        "interpretation_limit": "Exact BUILD.gn source pins do not resolve the GN args or prove a product compile profile."
    }
    OUTPUT.write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"audit={OUTPUT}; profiles={len(records)}; root_BUILD_bound={records[0]['files'][1]['model_dependency_binding']}")
    return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"BLOCKED: {error}", file=sys.stderr)
        raise SystemExit(2)
