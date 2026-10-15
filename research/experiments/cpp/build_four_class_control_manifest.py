from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Tuple

ROOT = Path(__file__).resolve().parents[3]
CONTROL_ROOT = ROOT / "research" / "tests" / "cpp_detector_controls"
OUTPUT = CONTROL_ROOT / "manifest.json"
BASE_ARGS = [
    "-std=c++17",
    "-g",
    "-O1",
    "-fno-omit-frame-pointer",
    "-pthread",
    "-no-pie",
]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data).hexdigest()


def source_entry(path: str) -> Dict[str, object]:
    full_path = ROOT / path
    data = full_path.read_bytes()
    return {
        "path": path,
        "bytes": len(data),
        "sha256": sha256_bytes(data),
        "git_blob_sha1": git_blob_sha1(data),
    }


def git_value(*args: str) -> str:
    return subprocess.check_output(
        ["git", *args], cwd=ROOT, text=True
    ).strip()


def control(
    *,
    control_id: str,
    detector_id: str,
    detector_version: str,
    rule_id: str,
    category: str,
    filename: str,
    patterns: List[str],
    root_cause: str,
    finding_count: int,
    message_contains: Optional[List[str]] = None,
    unknown_obligation_kinds: Optional[List[str]] = None,
    sanitizer: str = "thread",
    patch: Optional[Mapping[str, object]] = None,
) -> Dict[str, object]:
    family = "shared_ptr" if detector_id.endswith("shared_ptr_race") else "lifetime"
    path = f"research/tests/cpp_detector_controls/samples/{family}/{filename}"
    environment = {
        "ASAN_OPTIONS": "abort_on_error=1:detect_leaks=0:handle_segv=1"
    } if sanitizer == "address" else {
        "TSAN_OPTIONS": "halt_on_error=1:exitcode=66"
    }
    result: Dict[str, object] = {
        "id": control_id,
        "detector_id": detector_id,
        "detector_version": detector_version,
        "rule_id": rule_id,
        "category": category,
        "patterns": patterns,
        "expected_root_cause": root_cause,
        "source": source_entry(path),
        "expected_detector": {
            "status": "completed",
            "finding_count": finding_count,
            "message_contains": message_contains or [],
            "unknown_obligation_kinds": unknown_obligation_kinds or [],
            "interpretation": (
                "candidate/unassessed"
                if finding_count
                else "negative control only; not a safe verdict"
            ),
        },
        "build": {
            "compiler": "clang++",
            "language_standard": "c++17",
            "arguments": list(BASE_ARGS),
            "sanitizer": sanitizer,
            "environment": environment,
            "timeout_seconds": 60,
        },
        "run": {
            "arguments": [],
            "repeats": 3,
            "timeout_seconds": 45,
        },
        "expected_dynamic": {
            "outcome": "sanitizer_triggered" if category == "vulnerable" else "clean",
            "classification_boundary": (
                "controlled synthetic workload"
            ),
        },
    }
    if patch is not None:
        result["patch"] = dict(patch)
    return result


def patch_entry(
    *,
    patch_name: str,
    base_filename: str,
    fixed_filename: str,
    family: str,
) -> Dict[str, object]:
    base_path = (
        f"research/tests/cpp_detector_controls/samples/{family}/{base_filename}"
    )
    fixed_path = (
        f"research/tests/cpp_detector_controls/samples/{family}/{fixed_filename}"
    )
    patch_path = f"research/tests/cpp_detector_controls/patches/{patch_name}"
    patch_data = (ROOT / patch_path).read_bytes()
    return {
        "path": patch_path,
        "sha256": sha256_bytes(patch_data),
        "kind": "authored_control_remediation_patch",
        "upstream_status": "not_claimed_as_upstream_product_patch",
        "base_source": source_entry(base_path),
        "fixed_source": source_entry(fixed_path),
        "base_sha256": source_entry(base_path)["sha256"],
        "fixed_sha256": source_entry(fixed_path)["sha256"],
        "application_policy": "patch -p1 --fuzz=0 and exact fixed-byte comparison",
    }


def main() -> None:
    shared_detector = "ohscanner.cpp.shared_ptr_race"
    lifetime_detector = "ohscanner.cpp.lifetime"
    shared_patch_lock = patch_entry(
        patch_name="shared_delayed_singleton_explicit_lock.patch",
        base_filename="shared_vulnerable_delayed_singleton_plain.cpp",
        fixed_filename="shared_fixed_delayed_singleton_explicit_lock.cpp",
        family="shared_ptr",
    )
    shared_patch_atomic = patch_entry(
        patch_name="shared_atomic_protocol.patch",
        base_filename="shared_vulnerable_atomic_exchange_mixed.cpp",
        fixed_filename="shared_fixed_atomic_exchange_protocol.cpp",
        family="shared_ptr",
    )
    lifetime_patches = {
        "reset": patch_entry(
            patch_name="lifetime_reset_rebind.patch",
            base_filename="lifetime_vulnerable_reset_raw_alias.cpp",
            fixed_filename="lifetime_fixed_reset_rebind_patch.cpp",
            family="lifetime",
        ),
        "null": patch_entry(
            patch_name="lifetime_owner_null_rebind.patch",
            base_filename="lifetime_vulnerable_owner_null_assignment.cpp",
            fixed_filename="lifetime_fixed_owner_null_assignment_patch.cpp",
            family="lifetime",
        ),
        "replacement": patch_entry(
            patch_name="lifetime_owner_replacement_rebind.patch",
            base_filename="lifetime_vulnerable_owner_replacement.cpp",
            fixed_filename="lifetime_fixed_owner_replacement_patch.cpp",
            family="lifetime",
        ),
        "move": patch_entry(
            patch_name="lifetime_move_scope.patch",
            base_filename="lifetime_vulnerable_restricted_move_transfer.cpp",
            fixed_filename="lifetime_fixed_move_scope_patch.cpp",
            family="lifetime",
        ),
    }
    controls = [
        control(
            control_id="shared-vulnerable-delayed-singleton-plain",
            detector_id=shared_detector,
            detector_version="0.4.0",
            rule_id="ohcpp-shared-ptr-race-candidate-001",
            category="vulnerable",
            filename="shared_vulnerable_delayed_singleton_plain.cpp",
            patterns=["DelayedSingleton", "shared_ptr", "reset", "mixed lock/plain read"],
            root_cause="unprotected shared_ptr copy races with guarded reset",
            finding_count=1,
            message_contains=["candidate/unknown"],
            unknown_obligation_kinds=["synchronization_proof"],
        ),
        control(
            control_id="shared-vulnerable-atomic-exchange-mixed",
            detector_id=shared_detector,
            detector_version="0.4.0",
            rule_id="ohcpp-shared-ptr-race-candidate-001",
            category="vulnerable",
            filename="shared_vulnerable_atomic_exchange_mixed.cpp",
            patterns=["atomic exchange", "mixed atomic/non-atomic"],
            root_cause="atomic exchange races with ordinary shared_ptr read",
            finding_count=1,
            message_contains=["candidate/unknown"],
            unknown_obligation_kinds=["synchronization_proof"],
        ),
        control(
            control_id="shared-vulnerable-compare-exchange-mixed",
            detector_id=shared_detector,
            detector_version="0.4.0",
            rule_id="ohcpp-shared-ptr-race-candidate-001",
            category="vulnerable",
            filename="shared_vulnerable_compare_exchange_mixed.cpp",
            patterns=["atomic compare-exchange", "mixed atomic/non-atomic"],
            root_cause="atomic compare-exchange races with ordinary shared_ptr read",
            finding_count=1,
            message_contains=["candidate/unknown"],
            unknown_obligation_kinds=["synchronization_proof"],
        ),
        control(
            control_id="shared-fixed-delayed-singleton-explicit-lock",
            detector_id=shared_detector,
            detector_version="0.4.0",
            rule_id="ohcpp-shared-ptr-race-candidate-001",
            category="fixed",
            filename="shared_fixed_delayed_singleton_explicit_lock.cpp",
            patterns=["DelayedSingleton", "explicit lock", "reset"],
            root_cause="remediation moves every conflicting access under one mutex",
            finding_count=0,
            patch=shared_patch_lock,
        ),
        control(
            control_id="shared-fixed-atomic-exchange-protocol",
            detector_id=shared_detector,
            detector_version="0.4.0",
            rule_id="ohcpp-shared-ptr-race-candidate-001",
            category="fixed",
            filename="shared_fixed_atomic_exchange_protocol.cpp",
            patterns=["atomic exchange", "atomic compare-exchange", "atomic load"],
            root_cause="remediation removes every mixed ordinary access",
            finding_count=0,
            patch=shared_patch_atomic,
        ),
        control(
            control_id="shared-safe-explicit-lock-common-fp",
            detector_id=shared_detector,
            detector_version="0.4.0",
            rule_id="ohcpp-shared-ptr-race-candidate-001",
            category="safe",
            filename="shared_safe_explicit_lock_common_fp.cpp",
            patterns=["explicit lock", "common false-positive shape", "reset"],
            root_cause="all conflicting accesses share a reliable lexical mutex",
            finding_count=0,
        ),
        control(
            control_id="shared-safe-cross-class-same-member-name",
            detector_id=shared_detector,
            detector_version="0.4.0",
            rule_id="ohcpp-shared-ptr-race-candidate-001",
            category="safe",
            filename="shared_safe_cross_class_same_member_name.cpp",
            patterns=["same member name", "different class", "common false-positive shape"],
            root_cause="same member name is not cross-class ownership",
            finding_count=0,
        ),
        control(
            control_id="shared-unrelated-plain-pointer",
            detector_id=shared_detector,
            detector_version="0.4.0",
            rule_id="ohcpp-shared-ptr-race-candidate-001",
            category="unrelated",
            filename="shared_unrelated_plain_pointer.cpp",
            patterns=["stable raw pointer", "unrelated ownership"],
            root_cause="no shared_ptr member ownership shape exists",
            finding_count=0,
        ),
        control(
            control_id="lifetime-vulnerable-reset-raw-alias",
            detector_id=lifetime_detector,
            detector_version="0.3.0",
            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
            category="vulnerable",
            filename="lifetime_vulnerable_reset_raw_alias.cpp",
            patterns=["reset", "raw alias"],
            root_cause="raw alias is dereferenced after unique_ptr reset",
            finding_count=1,
            message_contains=["not proof of UAF"],
            sanitizer="address",
        ),
        control(
            control_id="lifetime-vulnerable-owner-null-assignment",
            detector_id=lifetime_detector,
            detector_version="0.3.0",
            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
            category="vulnerable",
            filename="lifetime_vulnerable_owner_null_assignment.cpp",
            patterns=["owner assignment", "raw alias"],
            root_cause="raw alias is dereferenced after owner null assignment",
            finding_count=1,
            message_contains=["owner assignment", "not proof of UAF"],
            sanitizer="address",
        ),
        control(
            control_id="lifetime-vulnerable-owner-replacement",
            detector_id=lifetime_detector,
            detector_version="0.3.0",
            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
            category="vulnerable",
            filename="lifetime_vulnerable_owner_replacement.cpp",
            patterns=["owner replacement", "raw alias"],
            root_cause="raw alias retains the previous object after owner replacement",
            finding_count=1,
            message_contains=["owner assignment", "not proof of UAF"],
            sanitizer="address",
        ),
        control(
            control_id="lifetime-vulnerable-restricted-move-transfer",
            detector_id=lifetime_detector,
            detector_version="0.3.0",
            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
            category="vulnerable",
            filename="lifetime_vulnerable_restricted_move_transfer.cpp",
            patterns=["restricted move transfer", "destination scope", "raw alias"],
            root_cause="destination owner scope ends before stale alias use",
            finding_count=1,
            message_contains=["move transfer", "not proof of UAF"],
            sanitizer="address",
        ),
        control(
            control_id="lifetime-fixed-reset-rebind-patch",
            detector_id=lifetime_detector,
            detector_version="0.3.0",
            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
            category="fixed",
            filename="lifetime_fixed_reset_rebind_patch.cpp",
            patterns=["reset", "unconditional rebinding", "raw alias"],
            root_cause="patch rebinds the alias to the current owner state before use",
            finding_count=0,
            sanitizer="address",
            patch=lifetime_patches["reset"],
        ),
        control(
            control_id="lifetime-fixed-owner-null-rebind-patch",
            detector_id=lifetime_detector,
            detector_version="0.3.0",
            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
            category="fixed",
            filename="lifetime_fixed_owner_null_assignment_patch.cpp",
            patterns=["owner assignment", "unconditional rebinding", "raw alias"],
            root_cause="patch clears or refreshes the alias after null assignment",
            finding_count=0,
            sanitizer="address",
            patch=lifetime_patches["null"],
        ),
        control(
            control_id="lifetime-fixed-owner-replacement-rebind-patch",
            detector_id=lifetime_detector,
            detector_version="0.3.0",
            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
            category="fixed",
            filename="lifetime_fixed_owner_replacement_patch.cpp",
            patterns=["owner replacement", "unconditional rebinding", "raw alias"],
            root_cause="patch refreshes the alias to the replacement object",
            finding_count=0,
            sanitizer="address",
            patch=lifetime_patches["replacement"],
        ),
        control(
            control_id="lifetime-fixed-move-scope-patch",
            detector_id=lifetime_detector,
            detector_version="0.3.0",
            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
            category="fixed",
            filename="lifetime_fixed_move_scope_patch.cpp",
            patterns=["restricted move transfer", "destination scope", "raw alias"],
            root_cause="patch keeps destination ownership alive through alias use",
            finding_count=0,
            sanitizer="address",
            patch=lifetime_patches["move"],
        ),
        control(
            control_id="lifetime-safe-stable-owner-pointer",
            detector_id=lifetime_detector,
            detector_version="0.3.0",
            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
            category="safe",
            filename="lifetime_safe_stable_owner_pointer.cpp",
            patterns=["stable owner pointer", "use-before-reset", "raw alias"],
            root_cause="alias use precedes invalidation while owner is stable",
            finding_count=0,
            sanitizer="address",
        ),
        control(
            control_id="lifetime-safe-shadowed-bindings",
            detector_id=lifetime_detector,
            detector_version="0.3.0",
            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
            category="safe",
            filename="lifetime_safe_shadowed_bindings.cpp",
            patterns=["scope shadowing", "common false-positive shape", "raw alias"],
            root_cause="same names denote distinct lexical bindings",
            finding_count=0,
            sanitizer="address",
        ),
        control(
            control_id="lifetime-safe-comment-false-positive",
            detector_id=lifetime_detector,
            detector_version="0.3.0",
            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
            category="safe",
            filename="lifetime_safe_comment_false_positive.cpp",
            patterns=["comments and literals", "common false-positive shape", "raw alias"],
            root_cause="invalidation and dereference occur only in comment/string data",
            finding_count=0,
            sanitizer="address",
        ),
        control(
            control_id="lifetime-unrelated-raw-pointer",
            detector_id=lifetime_detector,
            detector_version="0.3.0",
            rule_id="ohcpp-lifetime-unique-raw-alias-reset-001",
            category="unrelated",
            filename="lifetime_unrelated_raw_pointer.cpp",
            patterns=["stable raw pointer", "unrelated ownership"],
            root_cause="no unique_ptr owner/raw-alias invalidation shape exists",
            finding_count=0,
            sanitizer="address",
        ),
    ]
    snapshot_input = [
        {
            "path": item["source"]["path"],
            "sha256": item["source"]["sha256"],
            "git_blob_sha1": item["source"]["git_blob_sha1"],
        }
        for item in sorted(controls, key=lambda item: item["source"]["path"])
    ]
    snapshot_sha256 = sha256_bytes(
        json.dumps(
            snapshot_input,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    manifest = {
        "schema_version": 1,
        "package_id": "cpp-detector-four-class-controls-20261015",
        "evidence_scope": "synthetic_development_controls",
        "is_independent_holdout": False,
        "accuracy_metrics_permitted": False,
        "purpose": (
            "Repeatable positive/fixed/safe/unrelated controls for A-line "
            "shared_ptr and lifetime detectors; not real vulnerability truth."
        ),
        "provenance": {
            "repository": git_value("remote", "get-url", "origin"),
            "authoring_checkout": {
                "head": git_value("rev-parse", "HEAD"),
                "tree": git_value("rev-parse", "HEAD^{tree}"),
            },
            "snapshot_sha256": snapshot_sha256,
            "source_identity_policy": (
                "Each source binds repository-relative path, byte length, "
                "SHA-256 and Git blob SHA-1; run reports bind final checkout HEAD/tree."
            ),
        },
        "detectors": {
            "ohscanner.cpp.shared_ptr_race": {
                "version": "0.4.0",
                "rule_id": "ohcpp-shared-ptr-race-candidate-001",
                "candidate_cwe": "CWE-362",
            },
            "ohscanner.cpp.lifetime": {
                "version": "0.3.0",
                "rule_id": "ohcpp-lifetime-unique-raw-alias-reset-001",
                "candidate_cwe": "CWE-416",
            },
        },
        "controls": controls,
        "family_poc_harnesses": [
            {
                "detector_id": "ohscanner.cpp.shared_ptr_race",
                "module": "src.ohscanner.poc.cpp_shared_ptr_race",
                "scope": "DelayedSingleton preserved-source family harness",
            },
            {
                "detector_id": "ohscanner.cpp.lifetime",
                "module": "src.ohscanner.poc.cpp_lifetime_uaf",
                "scope": "unique_ptr/raw-alias ASan family harness",
            },
        ],
        "metric_policy": {
            "prohibited": ["precision", "recall", "false_positive_rate", "false_negative_rate"],
            "reason": "Synthetic development controls are not independent labelled holdout data.",
            "negative_control_rule": (
                "safe/unrelated zero findings is an expected narrow negative control, "
                "not a global safe or miss verdict."
            ),
        },
        "limitations": [
            "所有样本为自编 synthetic development controls，不是独立 holdout，也不能计算 Precision/Recall。",
            "fixed 项绑定可执行、零 fuzz 的 authored_control_remediation_patch，并要求 Detector 稳定拒绝；不冒充上游产品补丁。",
            "TSan/ASan 只证明受控 workload 中的局部内存/并发行为，不证明真实产品入口、攻击者控制、CIA 影响或可利用性。",
            "shared_ptr Detector 的原子 API 和互斥身份仍是窄词法模型，跨函数协议、锁别名、模板实例化和真实构建配置保持 unknown。",
            "lifetime Detector 不建模完整 CFG、异常、析构时序、跨函数 alias 或真实所有权图；0 告警不是安全证明。",
            "sanitizer 结果受编译器、调度、迭代数和 allocator 影响；必须记录 exact argv、版本、重复次数和全部运行。",
        ],
    }
    OUTPUT.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(OUTPUT)


if __name__ == "__main__":
    main()