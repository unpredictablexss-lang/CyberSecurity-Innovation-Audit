"""Build a fail-closed RC-JSPROXY product validation package.

This module consumes source-bound component evidence and optional product
evidence. It never changes candidate/review state and never promotes a case
without verified product build, entry/permission/deployment, product trace,
CIA and affected-scope evidence.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import subprocess
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple


VARIANTS = ("vulnerable", "fixed_control_mutex", "patched_atomic_minimal")
EXPECTED_COMPONENT = {
    "vulnerable": {"detector_findings": 2, "close_get_entry": "sanitizer_triggered", "race": "sanitizer_triggered"},
    "fixed_control_mutex": {"detector_findings": 0, "close_get_entry": "clean", "race": "clean"},
    "patched_atomic_minimal": {"detector_findings": 0, "close_get_entry": "clean", "race": "clean"},
}
PRODUCT_TARGET = "//foundation/distributeddatamgr/kv_store/interfaces/jskits/distributedkvstore:distributedkvstore"
PRODUCT_BUILD_COMMAND = [
    "bash",
    "build/build_scripts/build.sh",
    "--product-name",
    "rk3568",
    "--build-variant",
    "user",
    "--build-target",
    PRODUCT_TARGET,
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def read_json(path: Path) -> Dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _normalized_status(value: Any) -> str:
    return str(value or "").strip().lower()


def _is_verified(value: Any) -> bool:
    return _normalized_status(value) in {"verified", "verified_observed", "met"}


def _is_negative_verified(value: Any) -> bool:
    return _normalized_status(value) in {"verified_negative", "verified_not_observed"}


def _sha_valid(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value.lower())


def _find_runs(poc: Mapping[str, Any], mode: str) -> List[Mapping[str, Any]]:
    return [item for item in poc.get("runs", []) if item.get("mode") == mode and item.get("variant") in VARIANTS]


def summarize_component(poc: Mapping[str, Any], manifest: Mapping[str, Any]) -> Dict[str, Any]:
    obligations: List[Dict[str, Any]] = []
    source = poc.get("source", {})
    source_ok = bool(source.get("verified")) and source.get("blob") == manifest.get("source_blob")
    source_ok = source_ok and source.get("sha256") == manifest.get("source_sha256")
    ids_ok = (
        poc.get("package_id") == manifest.get("package_id")
        and poc.get("candidate_status") == "candidate/unknown"
        and int(poc.get("validated_vulnerability", -1)) == 0
    )
    detector = poc.get("detector", {})
    detector_ok = (
        detector.get("id") == manifest.get("detector_id")
        and detector.get("version") == manifest.get("detector_version")
        and detector.get("rule_id") == manifest.get("rule_id")
    )
    obligations.append({
        "id": "component_source_and_identity",
        "status": "met" if source_ok and ids_ok and detector_ok else "failed",
        "detail": "candidate/source/detector identity matches the fixed manifest",
    })

    detector_runs = {item.get("variant"): item for item in poc.get("detector_runs", [])}
    detector_matrix_ok = True
    detector_details: Dict[str, Any] = {}
    for variant, expected in EXPECTED_COMPONENT.items():
        record = detector_runs.get(variant, {})
        actual = int(record.get("finding_count", -1))
        detector_details[variant] = {"finding_count": actual, "expected": expected["detector_findings"]}
        detector_matrix_ok = detector_matrix_ok and actual == expected["detector_findings"] and record.get("status") == "completed"
    obligations.append({
        "id": "component_detector_three_party",
        "status": "met" if detector_matrix_ok else "failed",
        "detail": detector_details,
    })

    runs_by_key: Dict[Tuple[str, str], List[Mapping[str, Any]]] = defaultdict(list)
    for run in poc.get("runs", []):
        if run.get("variant") in VARIANTS and run.get("mode") in {"race", "close_get_entry"}:
            runs_by_key[(str(run.get("variant")), str(run.get("mode")))].append(run)

    dynamic_details: Dict[str, Any] = {}
    dynamic_ok = True
    for variant, expected in EXPECTED_COMPONENT.items():
        dynamic_details[variant] = {}
        for mode in ("race", "close_get_entry"):
            records = sorted(runs_by_key[(variant, mode)], key=lambda item: int(item.get("repeat", 0)))
            outcomes = [item.get("outcome") for item in records]
            repeats = [int(item.get("repeat", 0)) for item in records]
            mode_ok = repeats == [1, 2, 3] and all(item == expected[mode] for item in outcomes)
            dynamic_details[variant][mode] = {"repeats": repeats, "outcomes": outcomes, "expected": expected[mode]}
            dynamic_ok = dynamic_ok and mode_ok
    obligations.append({
        "id": "component_vulnerable_fixed_patched_repeats",
        "status": "met" if dynamic_ok else "failed",
        "detail": dynamic_details,
    })

    patch = poc.get("patch", {})
    patch_ok = _sha_valid(patch.get("sha256")) and _sha_valid(patch.get("fixed_source_sha256")) and _sha_valid(patch.get("patched_source_sha256"))
    obligations.append({
        "id": "component_patch_revalidation",
        "status": "met" if patch_ok and poc.get("outcome") == "stable_reproduced_and_patch_revalidated" else "failed",
        "detail": patch,
    })

    met = all(item["status"] == "met" for item in obligations)
    return {
        "status": "met" if met else "failed",
        "evidence_level": poc.get("evidence_level", "controlled_component_dynamic_reproduction"),
        "candidate_status": poc.get("candidate_status", "candidate/unknown"),
        "validated_vulnerability": poc.get("validated_vulnerability", 0),
        "obligations": obligations,
    }


def _artifact_verified(variant: Mapping[str, Any], expected_bindings: Optional[Mapping[str, Mapping[str, Any]]] = None) -> bool:
    artifact = variant.get("artifact", {})
    build_command = variant.get("build_command")
    return (
        _is_verified(variant.get("status"))
        and isinstance(build_command, list)
        and bool(build_command)
        and isinstance(artifact, dict)
        and isinstance(artifact.get("path"), str)
        and bool(artifact.get("path"))
        and _sha_valid(artifact.get("sha256"))
        and int(artifact.get("size", 0) or 0) > 0
        and isinstance(artifact.get("install_path"), str)
        and bool(artifact.get("install_path"))
        and _sha_valid(variant.get("source_manifest_sha256"))
        and _sha_valid(variant.get("toolchain_manifest_sha256"))
        and _sha_valid(variant.get("build_manifest_sha256"))
        and _sha_valid(variant.get("build_log_sha256"))
        and _sha_valid(variant.get("variant_source_sha256"))
        and ((variant.get("variant") == "vulnerable" and variant.get("patch_sha256") is None) or _sha_valid(variant.get("patch_sha256")))
        and (expected_bindings is None or _variant_binding_matches(variant, expected_bindings))
    )


def _variant_binding_matches(variant: Mapping[str, Any], expected_bindings: Mapping[str, Mapping[str, Any]]) -> bool:
    expected = expected_bindings.get(str(variant.get("variant")), {})
    return (
        variant.get("variant_source_sha256") == expected.get("source_sha256")
        and variant.get("patch_sha256") == expected.get("patch_sha256")
    )


def _entry_chain_verified(entry_chain: Mapping[str, Any]) -> bool:
    entries = entry_chain.get("entries", [])
    entry_names = " ".join(str(item.get("entry", "")) for item in entries).lower()
    required_names = ("getresultset", "closeresultset", "getentry", "asyncwork")
    entries_ok = isinstance(entries, list) and len(entries) >= 4 and all(name in entry_names for name in required_names)
    bindings_ok = bool(entries) and all(_sha_valid(item.get("source_sha256")) and _sha_valid(item.get("evidence_sha256")) for item in entries)
    boundaries = ("permission", "identity", "deployment")
    boundaries_ok = all(
        _is_verified(entry_chain.get(name, {}).get("status")) and _sha_valid(entry_chain.get(name, {}).get("evidence_sha256"))
        for name in boundaries
    )
    return _is_verified(entry_chain.get("status")) and entries_ok and bindings_ok and boundaries_ok


def _trace_verified(trace: Mapping[str, Any], artifact_by_variant: Mapping[str, str]) -> bool:
    variant = str(trace.get("variant", ""))
    events = trace.get("events", [])
    event_text = json.dumps(events, ensure_ascii=False).lower()
    required = ("closeresultset", "getentry", "setinstance", "getinstance")
    event_shape_ok = (
        isinstance(events, list)
        and len(events) >= 4
        and all(name in event_text for name in required)
        and len({str(item.get("thread_id", "")) for item in events}) >= 2
        and all(_sha_valid(item.get("source_sha256")) for item in events)
        and [item.get("sequence") for item in events] == sorted(item.get("sequence") for item in events)
    )
    overlap = trace.get("overlap", {})
    overlap_ok = bool(overlap.get("start_event")) and bool(overlap.get("end_event"))
    artifact_ok = trace.get("product_artifact_sha256") == artifact_by_variant.get(variant)
    outcome = _normalized_status(trace.get("outcome"))
    if variant == "vulnerable":
        outcome_ok = outcome in {"race_observed", "sanitizer_triggered", "crash_observed"}
    else:
        outcome_ok = outcome in {"clean", "fixed_clean", "patched_clean"}
    return (
        _is_verified(trace.get("status"))
        and _sha_valid(trace.get("trace_sha256"))
        and event_shape_ok
        and overlap_ok
        and artifact_ok
        and outcome_ok
    )


def _traces_verified(traces: Iterable[Mapping[str, Any]], artifact_by_variant: Mapping[str, str]) -> bool:
    grouped: Dict[str, List[Mapping[str, Any]]] = defaultdict(list)
    for trace in traces:
        grouped[str(trace.get("variant", ""))].append(trace)
    for variant in VARIANTS:
        records = sorted(grouped.get(variant, []), key=lambda item: int(item.get("repeat", 0) or 0))
        if [item.get("repeat") for item in records] != [1, 2, 3]:
            return False
        if not all(_trace_verified(item, artifact_by_variant) for item in records):
            return False
    return True


def _cia_verified(cia: Mapping[str, Any]) -> bool:
    states = [cia.get(name, {}).get("status") for name in ("availability", "integrity", "confidentiality")]
    if not all(_is_verified(item) or _is_negative_verified(item) for item in states):
        return False
    if not any(_is_verified(item) for item in states):
        return False
    return all(
        _sha_valid(cia.get(name, {}).get("evidence_sha256")) and bool(cia.get(name, {}).get("method"))
        for name in ("availability", "integrity", "confidentiality")
    )


def _scope_verified(scope: Mapping[str, Any]) -> bool:
    modules = scope.get("modules", [])
    versions = scope.get("versions", {})
    branches = scope.get("branches", {})
    return (
        isinstance(modules, list)
        and bool(modules)
        and _is_verified(versions.get("status"))
        and bool(versions.get("items"))
        and _is_verified(branches.get("status"))
        and bool(branches.get("items"))
        and all(_sha_valid(item.get("evidence_sha256")) for item in versions.get("items", []))
        and all(_sha_valid(item.get("evidence_sha256")) for item in branches.get("items", []))
    )


def _cwe_cve_verified(binding: Mapping[str, Any]) -> bool:
    cwe = binding.get("cwe", {})
    cve = binding.get("cve", {})
    cve_ok = _normalized_status(cve.get("status")) in {"assigned_verified", "not_assigned_with_audited_search"}
    return (
        _is_verified(cwe.get("status"))
        and cwe.get("id") == "CWE-362"
        and _sha_valid(cwe.get("evidence_sha256"))
        and bool(cwe.get("basis"))
        and cve_ok
        and _sha_valid(cve.get("evidence_sha256"))
        and bool(cve.get("basis"))
    )


def evaluate_product(
    product: Optional[Mapping[str, Any]],
    expected_variant_bindings: Optional[Mapping[str, Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    product = product or {}
    top_level_ok = product.get("kind") == "rc_jsproxy_product_evidence_v1" and _is_verified(product.get("status"))
    builds = product.get("product_build", {}).get("variants", [])
    artifact_by_variant = {
        str(item.get("variant")): str((item.get("artifact") or {}).get("sha256", ""))
        for item in builds
        if isinstance(item, dict)
    }
    obligations = [
        {
            "id": "product_build_and_artifact_identity",
            "status": "met" if set(artifact_by_variant) == set(VARIANTS) and all(_artifact_verified(item, expected_variant_bindings) for item in builds) else "unknown",
            "detail": "three product variants require exact source/toolchain manifests, build command, artifact path/hash/size/install path",
        },
        {
            "id": "real_entry_chain",
            "status": "met" if _entry_chain_verified(product.get("entry_chain", {})) else "unknown",
            "detail": "JS/NAPI call chain plus permission, process identity and deployment boundary must all be verified",
        },
        {
            "id": "product_interleaving_trace",
            "status": "met" if _traces_verified(product.get("trigger_traces", []), artifact_by_variant) else "unknown",
            "detail": "three repeats per variant require product thread IDs, closeResultSet/getEntry overlap and variant-bound artifacts",
        },
        {
            "id": "cia_impact",
            "status": "met" if _cia_verified(product.get("cia_impact", {})) else "unknown",
            "detail": "availability/integrity/confidentiality need measured claims and evidence; one concrete observed impact is required",
        },
        {
            "id": "affected_modules_versions_branches",
            "status": "met" if _scope_verified(product.get("affected_scope", {})) else "unknown",
            "detail": "module, affected version and branch membership require source/history/product evidence",
        },
        {
            "id": "cwe_cve_binding",
            "status": "met" if _cwe_cve_verified(product.get("cwe_cve", {})) else "unknown",
            "detail": "CWE-362 basis is required; CVE must be assigned/verified or supported by an audited no-assignment search",
        },
    ]
    unknowns = product.get("unknowns", [])
    blocking_unknowns = [
        item for item in unknowns
        if _normalized_status(item.get("severity")) in {"critical", "high"}
    ]
    met = top_level_ok and all(item["status"] == "met" for item in obligations) and not blocking_unknowns
    return {
        "status": "met" if met else "unknown",
        "promotion_gate": "met" if met else "not_met",
        "recommended_status": "confirmed_reportable_review" if met else "candidate/unknown",
        "status_change_requires_owner_authorization": True,
        "obligations": obligations,
        "blocking_unknowns": blocking_unknowns,
        "remaining_unknowns": unknowns,
    }


def _git_bytes(repo: Path, revision: str, path: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), "show", f"{revision}:{path}"],
        capture_output=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git show failed for {revision}:{path}: {result.stderr.decode('utf-8', 'replace')}")
    return result.stdout


def _fixed_control_source(source: str) -> str:
    if "#include <mutex>" not in source:
        source = source.replace("#include <memory>", "#include <memory>\n#include <mutex>", 1)
    source = source.replace(
        "        instance_ = std::move(instance);",
        "        std::lock_guard<std::mutex> lock(instanceMutex_);\n        instance_ = std::move(instance);",
        1,
    )
    source = source.replace(
        "        return instance_;",
        "        std::lock_guard<std::mutex> lock(instanceMutex_);\n        return instance_;",
        1,
    )
    source = source.replace(
        "    std::shared_ptr<T> instance_;",
        "    mutable std::mutex instanceMutex_;\n    std::shared_ptr<T> instance_;",
        1,
    )
    return source


def _patched_atomic_source(source: str) -> str:
    if "#include <atomic>" not in source:
        source = source.replace("#include <memory>", "#include <memory>\n#include <atomic>", 1)
    source = source.replace(
        "        instance_ = std::move(instance);",
        "        std::atomic_store(&instance_, std::move(instance));",
        1,
    )
    source = source.replace(
        "        return instance_;",
        "        return std::atomic_load(&instance_);",
        1,
    )
    return source


def patch_applies_to_index(repo: Path, patch: bytes) -> bool:
    result = subprocess.run(
        ["git", "-C", str(repo), "apply", "--cached", "--check", "-"],
        input=patch,
        capture_output=True,
        check=False,
    )
    return result.returncode == 0


def generate_patch(original: bytes, revised: bytes) -> bytes:
    return "".join(
        difflib.unified_diff(
            original.decode("utf-8").splitlines(keepends=True),
            revised.decode("utf-8").splitlines(keepends=True),
            fromfile="a/frameworks/common/js_proxy.h",
            tofile="b/frameworks/common/js_proxy.h",
        )
    ).encode("utf-8")


def product_preflight(product_source_root: Optional[Path]) -> Dict[str, Any]:
    if product_source_root is None:
        return {"status": "unknown", "reason": "no product source root supplied"}
    root = product_source_root.resolve()
    checks = {
        ".gn": (root / ".gn").is_file(),
        "build/build_scripts/build.sh": (root / "build/build_scripts/build.sh").is_file(),
        "build/scripts/entry.py": (root / "build/scripts/entry.py").is_file(),
        "foundation/distributeddatamgr/kv_store/BUILD.gn": (root / "foundation/distributeddatamgr/kv_store/BUILD.gn").is_file(),
        "device/board/hihope/rk3568": (root / "device/board/hihope/rk3568").is_dir(),
        "vendor/hihope/rk3568": (root / "vendor/hihope/rk3568").is_dir(),
        "prebuilts/build-tools": (root / "prebuilts/build-tools").is_dir(),
        "prebuilts/python": (root / "prebuilts/python").is_dir(),
    }
    missing = [name for name, present in checks.items() if not present]
    return {
        "status": "ready" if not missing else "blocked",
        "root": str(root),
        "checks": checks,
        "missing": missing,
        "build_command_candidate": PRODUCT_BUILD_COMMAND,
        "build_target": PRODUCT_TARGET,
    }


def build_package(
    manifest_path: Path,
    component_poc_path: Path,
    product_evidence_path: Optional[Path],
    product_source_root: Optional[Path],
    source_repo: Optional[Path],
    output_dir: Path,
) -> Dict[str, Any]:
    manifest = read_json(manifest_path)
    component_poc = read_json(component_poc_path)
    product = read_json(product_evidence_path) if product_evidence_path else None

    fixed_patch = b""
    atomic_patch = b""
    patch_records: List[Dict[str, Any]] = []
    expected_variant_bindings: Dict[str, Dict[str, Any]] = {
        "vulnerable": {"source_sha256": manifest.get("source_sha256"), "patch_sha256": None},
        "fixed_control_mutex": {"source_sha256": component_poc.get("patch", {}).get("fixed_source_sha256"), "patch_sha256": "unavailable"},
        "patched_atomic_minimal": {"source_sha256": component_poc.get("patch", {}).get("patched_source_sha256"), "patch_sha256": "unavailable"},
    }
    if source_repo is not None:
        original = _git_bytes(source_repo, str(manifest["commit"]), str(manifest["source_path"]))
        if sha256_bytes(original) != manifest.get("source_sha256"):
            raise RuntimeError("source repo blob hash does not match candidate manifest")
        fixed_patch = generate_patch(original, _fixed_control_source(original.decode("utf-8")).encode("utf-8"))
        atomic_patch = generate_patch(original, _patched_atomic_source(original.decode("utf-8")).encode("utf-8"))
        expected_variant_bindings["fixed_control_mutex"]["patch_sha256"] = sha256_bytes(fixed_patch)
        expected_variant_bindings["patched_atomic_minimal"]["patch_sha256"] = sha256_bytes(atomic_patch)
        if not patch_applies_to_index(source_repo, fixed_patch) or not patch_applies_to_index(source_repo, atomic_patch):
            raise RuntimeError("generated repair patch does not apply to the audited Git index")
        patch_records = [
            {"variant": "fixed_control_mutex", "path": "fixed_control_mutex.patch", "sha256": sha256_bytes(fixed_patch), "role": "independent safe control", "git_apply_cached_check": "passed"},
            {"variant": "patched_atomic_minimal", "path": "patched_atomic_minimal.patch", "sha256": sha256_bytes(atomic_patch), "role": "minimal proposed repair", "git_apply_cached_check": "passed"},
        ]
    component = summarize_component(component_poc, manifest)
    product_gate = evaluate_product(product, expected_variant_bindings)
    preflight = product_preflight(product_source_root)

    product_build_method = {
        "status": "source_derived_unexecuted" if preflight.get("status") != "ready" else "preflight_ready_unexecuted",
        "source_root_requirement": "full OpenHarmony source tree with manifest-pinned project commits",
        "product_name": "rk3568",
        "build_variant": "user",
        "build_target": PRODUCT_TARGET,
        "candidate_command_argv": PRODUCT_BUILD_COMMAND,
        "artifact_hash_requirement": ["path", "sha256", "size", "install_path"],
        "variant_preparation": {
            "vulnerable": "exact audited commit/tree without repair",
            "fixed_control_mutex": "apply fixed_control_mutex.patch to the exact audited source",
            "patched_atomic_minimal": "apply patched_atomic_minimal.patch to the exact audited source",
        },
        "current_artifact_hashes": {
            item.get("variant"): item.get("artifact")
            for item in (product or {}).get("product_build", {}).get("variants", [])
            if isinstance(item, dict)
        },
        "preflight": preflight,
    }

    all_ok = component["status"] == "met" and product_gate["promotion_gate"] == "met"
    final_status = "confirmed/reportable-review-ready" if all_ok else "candidate/unknown"
    validation = {
        "schema_version": 1,
        "kind": "rc_jsproxy_product_validation_package",
        "package_id": "rc-jsproxy-product-gate-20261015",
        "selected_review_group": "RC-JSPROXY",
        "final_status": final_status,
        "validated_vulnerability": 1 if all_ok else 0,
        "promotion_policy": {
            "candidate_default": "candidate/unknown",
            "promotion_requires": [
                "verified product build and artifact identity",
                "verified real entry chain, permission, app identity and deployment boundary",
                "verified product-level interleaving trace",
                "verified CIA impact and affected scope",
                "verified CWE/CVE binding basis",
                "independent owner/reviewer authorization",
            ],
            "no_auto_promotion": True,
        },
        "fixed_identity": {
            "repository": manifest.get("repository"),
            "commit": manifest.get("commit"),
            "tree": manifest.get("git_tree"),
            "source_path": manifest.get("source_path"),
            "source_blob": manifest.get("source_blob"),
            "source_sha256": manifest.get("source_sha256"),
        },
        "component_validation": component,
        "product_build_method": product_build_method,
        "product_validation": product_gate,
        "trigger_conditions": [
            "same application obtains a result set through SingleKVStore.getResultSet",
            "synchronous KVStoreResultSet.getEntry runs on the JS thread",
            "SingleKVStore.closeResultSet NapiQueue execute overlaps the synchronous read",
            "the overlap is captured in the product process with thread IDs and queue/source locations",
        ],
        "source_visible_call_path": component_poc.get("call_path_sources", []),
        "cia_requirement": {
            "availability": "measured process/API failure or no failure under repeated product trigger",
            "integrity": "measured returned-entry or state divergence, or verified negative",
            "confidentiality": "same-app/cross-app/device disclosure boundary, or verified negative",
        },
        "input_files": {
            "candidate_manifest": {"path": str(manifest_path), "sha256": sha256_file(manifest_path)},
            "component_poc": {"path": str(component_poc_path), "sha256": sha256_file(component_poc_path)},
            "product_evidence": {"path": str(product_evidence_path), "sha256": sha256_file(product_evidence_path)} if product_evidence_path else None,
            "generator": {"path": "src/ohscanner/poc/rc_jsproxy_product_gate.py", "sha256": sha256_file(Path(__file__).resolve())},
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    write_json(output_dir / "validation.json", validation)

    if source_repo is not None:
        (output_dir / "fixed_control_mutex.patch").write_bytes(fixed_patch)
        (output_dir / "patched_atomic_minimal.patch").write_bytes(atomic_patch)
    markdown = render_markdown(validation, patch_records)
    (output_dir / "validation.md").write_text(markdown, encoding="utf-8")

    manifest_out: Dict[str, Any] = {
        "schema_version": 1,
        "kind": "rc_jsproxy_product_validation_package_manifest",
        "package_id": validation["package_id"],
        "files": {},
        "patches": patch_records,
        "generated_by": {"path": "src/ohscanner/poc/rc_jsproxy_product_gate.py", "sha256": sha256_file(Path(__file__).resolve())},
    }
    for path in sorted(output_dir.iterdir()):
        if path.is_file() and path.name != "package-manifest.json":
            manifest_out["files"][path.name] = {"sha256": sha256_file(path), "size": path.stat().st_size}
    write_json(output_dir / "package-manifest.json", manifest_out)
    return validation


def render_markdown(validation: Mapping[str, Any], patch_records: Sequence[Mapping[str, Any]]) -> str:
    component = validation["component_validation"]
    product = validation["product_validation"]
    method = validation["product_build_method"]
    lines = [
        "# RC-JSPROXY 真实产品闭环最小验证包",
        "",
        f"- 最终状态：`{validation['final_status']}`",
        f"- `validated_vulnerability`：`{validation['validated_vulnerability']}`",
        f"- 候选组：`{validation['selected_review_group']}`",
        "- 本包不修改历史候选、review、报告或漏洞状态；只有产品级强制义务全部满足并经负责人/独立复核授权后，才进入 confirmed/reportable 审核。",
        "",
        "## 1. 固定身份与候选级证据",
        "",
        f"- repository：`{validation['fixed_identity']['repository']}`",
        f"- commit/tree：`{validation['fixed_identity']['commit']}` / `{validation['fixed_identity']['tree']}`",
        f"- source：`{validation['fixed_identity']['source_path']}` blob `{validation['fixed_identity']['source_blob']}` SHA-256 `{validation['fixed_identity']['source_sha256']}`",
        f"- 组件级三方复验：`{component['status']}`；证据级别：`{component['evidence_level']}`",
        "",
        "## 2. 真实产品构建方式和产物 hash",
        "",
        f"- 构建入口：`{' '.join(method['candidate_command_argv'])}`",
        f"- 目标：`{method['build_target']}`；产品：`{method['product_name']}`；variant：`{method['build_variant']}`",
        f"- 方法状态：`{method['status']}`；当前 preflight：`{method['preflight'].get('status')}`",
        f"- 产品构建义务：`{next(item['status'] for item in product['obligations'] if item['id'] == 'product_build_and_artifact_identity')}`",
        "- 当前真实构建产物 hash：未生成/未证明。缺任何 vulnerable/fixed/patched 产物的 path、SHA-256、size、install path，必须保持 unknown。",
        "",
        "## 3. 真实入口、调用链、权限/身份/部署边界",
        "",
        "- 源码可见链：`getResultSet -> NapiQueue::AsyncWork -> SetInstance`、`getEntry -> GetInstance`、`closeResultSet -> NapiQueue::AsyncWork -> GetInstance/SetInstance(nullptr)/CloseResultSet`。",
        f"- 产品入口/边界义务：`{next(item['status'] for item in product['obligations'] if item['id'] == 'real_entry_chain')}`。",
        "- 当前只能证明源码可见入口；产品包解析、app identity、permission grant/deny、user/sandbox、跨应用/IPC/remote 面仍是 unknown，不能作为攻击者控制证明。",
        "",
        "## 4. 可重复触发条件和产品级交错 trace",
        "",
        "- 固定触发序列：同一应用先 `getResultSet`，在 JS 线程持续 `getEntry`，同时异步 `closeResultSet` 的 execute 与读取重叠。",
        f"- 产品交错 trace 义务：`{next(item['status'] for item in product['obligations'] if item['id'] == 'product_interleaving_trace')}`。",
        "- 产品 trace 必须记录每轮 thread ID、JS/async queue、`SetInstance/GetInstance`、`closeResultSet/getEntry` 源位置、重叠起止事件和产品 artifact SHA-256。Harness TSan trace 不是产品 trace。",
        "",
        "## 5. CIA 影响",
        "",
        "| 维度 | 要求 | 当前状态 |",
        "|---|---|---|",
        "| 可用性 | 产品进程/API 失败率、崩溃或稳定无故障测量 | 产品级 unknown；Harness 仅证明 race |",
        "| 完整性 | 返回 entry/状态是否偏移、损坏或误读 | unknown |",
        "| 机密性 | 同应用、跨应用、跨设备数据暴露边界 | 未证明，不作泄露声明 |",
        "",
        f"- CIA 义务：`{next(item['status'] for item in product['obligations'] if item['id'] == 'cia_impact')}`。",
        "",
        "## 6. vulnerable / fixed / patched 三方重复验证",
        "",
        "| variant | 组件级 close_get_entry | 产品级重复 |",
        "|---|---|---|",
    ]
    for variant in VARIANTS:
        comp = component["obligations"][2]["detail"].get(variant, {}).get("close_get_entry", {})
        lines.append(f"| `{variant}` | `{comp.get('outcomes', [])}` | 3 次产品级 trace 要求，当前未证明 |")
    lines += [
        "",
        "组件级已有证据是 exact-header Harness/PoC：vulnerable 3/3 TSan 触发，mutex fixed control 3/3 clean，atomic patch 3/3 clean。它不能替代真实产品构建/运行。",
        "",
        "## 7. 影响模块、版本、分支和修复重验",
        "",
        "- 影响模块候选：`frameworks/common/js_proxy.h`、`js_single_kv_store.cpp`、`js_kv_store_resultset.cpp`、`napi_queue.cpp`。",
        "- 精确 commit/tree 是已绑定事实；版本和分支成员关系必须用固定 tag/branch/product image manifest 证明，当前保持 unknown。",
        f"- 修复/范围义务：`{next(item['status'] for item in product['obligations'] if item['id'] == 'affected_modules_versions_branches')}`。",
        "- proposed atomic patch 与 fixed mutex control 必须在相同真实产品 build/profile 下分别构建并重验，不能只用组件级 clean 代替。",
        "",
        "## 8. CWE/CVE 绑定依据",
        "",
        "- 主绑定：`CWE-362`，依据是同一 `shared_ptr` owner 的非同步写/读及 TSan race；不是仅凭 AST 命中。",
        "- `CWE-416` 只有在产品级 UAF/内存生命周期证据成立时才可作为后果；当前不绑定为已证实后果。",
        "- CVE：本地证据没有 assigned CVE。必须保存 CVE/NVD/上游公告检索范围和检索时间；无 assignment 不等于无漏洞。",
        f"- CWE/CVE 义务：`{next(item['status'] for item in product['obligations'] if item['id'] == 'cwe_cve_binding')}`。",
        "",
        "## 9. 审计产物与剩余 unknown",
        "",
    ]
    for item in product.get("remaining_unknowns", []):
        lines.append(f"- `{item.get('id', 'unknown')}` [{item.get('severity', 'unknown')}]：{item.get('question', '未填写')}")
    if not product.get("remaining_unknowns"):
        lines.append("- 当前产品证据没有结构化 unknown 列表；这本身不能被解释为没有 unknown。")
    lines += [
        "",
        "### 产物",
        "",
    ]
    for record in patch_records:
        lines.append(f"- `{record['path']}` SHA-256 `{record['sha256']}`（{record['role']}）")
    lines += [
        "- `validation.json`：机器可读义务矩阵、输入 hash 和 fail-closed 结论。",
        "- `package-manifest.json`：本目录产物 hash 清单。",
        "",
        "## 重放",
        "",
        "```text",
        "python -m src.ohscanner.poc.rc_jsproxy_product_gate \\",
        "  --candidate-manifest src/ohscanner/poc/harnesses/cpp_shared_ptr_jsproxy/manifest.json \\",
        "  --component-poc outputs/poc/shared-ptr-jsproxy-supplement-20261015/run-002/poc.json \\",
        "  --product-evidence research/evidence/cpp/rc_jsproxy_product_gate_20261015/product-evidence.json \\",
        "  --product-source-root E:/网安/_product_targets \\",
        "  --source-repo E:/网安/audit-sources-20261014/home/audit/openharmony-audit/perf-corpus/distributeddatamgr_kv_store \\",
        "  --output-dir outputs/reports/rc-jsproxy-product-gate-20261015",
        "```",
        "",
    ]
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-manifest", type=Path, required=True)
    parser.add_argument("--component-poc", type=Path, required=True)
    parser.add_argument("--product-evidence", type=Path)
    parser.add_argument("--product-source-root", type=Path)
    parser.add_argument("--source-repo", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    validation = build_package(
        args.candidate_manifest,
        args.component_poc,
        args.product_evidence,
        args.product_source_root,
        args.source_repo,
        args.output_dir,
    )
    print(json.dumps({
        "final_status": validation["final_status"],
        "validated_vulnerability": validation["validated_vulnerability"],
        "component_validation": validation["component_validation"]["status"],
        "product_gate": validation["product_validation"]["promotion_gate"],
        "output_dir": str(args.output_dir),
    }, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
