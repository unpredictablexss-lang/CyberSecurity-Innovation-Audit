from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

ROOT = Path(r"D:\openHarmonyScanner\outputs\01a14d00-bc78-7ac2-9520-210d4b92b1ac")
EVIDENCE = ROOT / "evidence"
SANDBOX_IMAGE = "sha256:e92d5365460142169ddd21d489bc9157d003c61e3382351c8f8516f3e38f96ae"


def load(name: str):
    with (EVIDENCE / name).open("r", encoding="utf-8") as stream:
        return json.load(stream)


def source_binding(diagnostic_id: str, check: dict, diagnostic: dict) -> dict:
    return {
        "diagnostic_id": diagnostic_id,
        "expected_source_sha256": diagnostic.get("source_sha256"),
        "actual_source_sha256": check.get("actual_source_sha256"),
        "source_sha256_matches": check.get("source_sha256_matches"),
        "git_blob_oid": check.get("git_blob_oid"),
        "line_exists": check.get("line_exists"),
        "line_text": check.get("line_text"),
        "source_binding": diagnostic.get("source_binding"),
    }


def obligations_shared_ptr() -> list[str]:
    return [
        "补齐方法级别名/所有权转移路径，证明 shared_ptr 读写是否真正并发交错",
        "证明析构时序、guard dominance 与同步原语覆盖全部共享访问",
        "给出目标构建配置、线程模型和攻击者可控调度/触发条件",
        "证明具体 CIA 影响，而非仅凭语法命中或通用 TSan 控制",
    ]


def obligations_ipc_auth() -> list[str]:
    return [
        "建立 Binder/IPC 入口、调用者 UID/PID/权限域与 upstream policy 的完整链路",
        "证明缺失 guard 支配所有到敏感操作的可达路径，而非仅局部函数片段",
        "证明攻击者可控输入可绕过授权并产生具体 CIA 影响",
    ]


def obligations_capability() -> list[str]:
    return [
        "证明导出对象/FD 的授权策略与 capability owner 边界",
        "证明调用者能够从真实 IPC 入口取得越权能力并到达敏感操作",
        "证明具体 CIA 影响；对象可导出本身不等于越权能力泄露",
    ]


def obligations_copy_range() -> list[str]:
    return [
        "如仍主张 CWE-125，需要给出绕过 cfgLen <= 0 与 cfgLen > MAX_LEN 的产品级触发路径",
        "在完整目标构建中复现越界读及返回相邻内存的 CIA 影响",
    ]


def obligations_relay() -> list[str]:
    return [
        "补充 descriptor 解析边界、输入长度与目标缓冲区容量的完整数据流",
        "证明真实 IPC 入口、可控触发条件和具体 CIA 影响",
    ]


def static_shared_ptr(diagnostic: dict) -> dict:
    return {
        "review_scope": "syntax_candidate_without_complete_concurrency_proof",
        "guard_dominance": {"status": "not_established", "finding": "扫描证据未给出支配并发访问的锁、原子操作或生命周期 guard。"},
        "ownership_atomicity": {"status": "not_established", "finding": "未绑定方法级所有权转移、别名、析构时序和 shared_ptr 原子性证明。"},
        "entry_privilege_boundary": {"status": "not_established", "finding": "语法命中未建立真实入口或攻击者权限边界。"},
        "reachable_sensitive_operation": {"status": "not_established", "finding": "未证明从可控并发交错到 UAF 或其他敏感操作的可达路径。"},
        "attacker_controlled_trigger": {"status": "not_established", "finding": "未证明攻击者可控线程调度、销毁时序或输入。"},
        "cia_impact": {"status": "not_established", "finding": "未证明机密性、完整性或可用性的具体影响。"},
    }


def static_copy_range(_: dict) -> dict:
    return {
        "review_scope": "source_excerpt_plus_reduced_source_derived_model",
        "guard_dominance": {"status": "established", "finding": "cfgLen <= 0 和 cfgLen > MAX_LEN(1024) 在 ReadBuffer/new/copy 之前拒绝；目标容量与 cfgLen 一致。"},
        "ownership_atomicity": {"status": "established_for_copy", "finding": "dataBuffer 与 cfgData 均以 cfgLen 为界，memcpy_s 两端长度一致，失败时释放目标缓冲区。"},
        "entry_privilege_boundary": {"status": "partial", "finding": "map_member_ptr code 12808 可达该 callback stub，但未证明具体调用者权限域。"},
        "reachable_sensitive_operation": {"status": "negated_for_cwe125", "finding": "现有路径只执行有界拷贝，未展示越界读。"},
        "attacker_controlled_trigger": {"status": "partial", "finding": "cfgLen 来自 Parcel，但负值/零值/超上限值均被拒绝。"},
        "cia_impact": {"status": "not_established", "finding": "未展示返回相邻内存或其他 CIA 影响。"},
    }


def static_capability(diagnostic: dict) -> dict:
    repo = diagnostic["repository"]
    file = diagnostic["file"]
    if "test/unittest" in file or "test/services" in file:
        return {
            "review_scope": "out_of_scope_test_code",
            "guard_dominance": {"status": "not_applicable", "finding": "候选位于测试代码，不作为产品边界漏洞证明。"},
            "ownership_atomicity": {"status": "not_applicable", "finding": "测试对象/导出不等同产品 capability。"},
            "entry_privilege_boundary": {"status": "out_of_scope", "finding": "测试入口不进入产品暴露面。"},
            "reachable_sensitive_operation": {"status": "out_of_scope", "finding": "不评估产品敏感操作可达性。"},
            "attacker_controlled_trigger": {"status": "out_of_scope", "finding": "测试触发不作为攻击面证据。"},
            "cia_impact": {"status": "not_established", "finding": "未建立产品 CIA 影响。"},
        }
    if repo == "openharmony/systemabilitymgr_samgr":
        return {
            "review_scope": "production_ipc_with_guard_context",
            "guard_dominance": {"status": "established_in_excerpt", "finding": "导出前可见 CheckGetSAPermission/CheckGetRemoteSAPermission、用户/远端检查或 PengLai/权限 guard；扫描器未将这些 guard 归一化为授权。"},
            "ownership_atomicity": {"status": "not_applicable", "finding": "候选是远端对象导出，不是共享对象生命周期竞争。"},
            "entry_privilege_boundary": {"status": "established_for_reported_path", "finding": "报告路径显示导出受权限检查支配；未发现绕过分支。"},
            "reachable_sensitive_operation": {"status": "authorized_service_lookup", "finding": "导出的是注册系统能力查询结果，现有证据未显示越权访问。"},
            "attacker_controlled_trigger": {"status": "partial", "finding": "IPC 参数可控，但授权 guard 支配导出。"},
            "cia_impact": {"status": "negated_for_reported_path", "finding": "未证明未授权 capability 离开 owner，故不构成 CWE-926/668 的已确认漏洞。"},
        }
    if repo == "openharmony/distributeddatamgr_data_share":
        detail = "OpenFile/OpenFileInner 的 provider 端授权可能在抽象实现内部执行；局部 Stub 片段不能证明授权缺失。"
    elif repo == "openharmony/ai_intelligent_voice_framework":
        detail = "CreateEngine 返回 engine->AsObject() 看起来是预期服务 API；未证明该对象越过授权 owner 边界。"
    elif repo == "openharmony/communication_wifi":
        detail = "OnRemoteRequest 先验证 interface token，再按 code 返回 GetWifiRemote 结果；未证明未授权 capability 泄露。"
    else:
        detail = "未建立 capability owner、调用者权限域与越权导出之间的完整证据链。"
    return {
        "review_scope": "production_ipc_policy_incomplete",
        "guard_dominance": {"status": "partial", "finding": detail},
        "ownership_atomicity": {"status": "not_established", "finding": "未证明对象/FD ownership 越过合法授权边界。"},
        "entry_privilege_boundary": {"status": "partial", "finding": "存在 IPC dispatch 或 token 检查，但完整权限策略未闭合。"},
        "reachable_sensitive_operation": {"status": "not_established", "finding": "导出行为可见，但未证明可执行越权敏感操作。"},
        "attacker_controlled_trigger": {"status": "partial", "finding": "IPC 输入/调用路径可控，但授权结果未被反证。"},
        "cia_impact": {"status": "not_established", "finding": "未证明具体 CIA 影响。"},
    }


def static_auth(diagnostic: dict) -> dict:
    repo = diagnostic["repository"]
    file = diagnostic["file"]
    if "test/" in file:
        finding = "候选位于测试探针/测试代码，不作为产品授权绕过证据。"
    elif repo == "openharmony/multimedia_camera_framework":
        finding = "CreateCameraDevice 显式区分 isPrivilegeApp 与非特权处理；局部路径未证明未授权调用者绕过策略。"
    elif repo == "openharmony/distributeddatamgr_data_share":
        finding = "OpenFileInner 局部片段未识别授权，但 OpenFile/provider 抽象内部可能执行 URI/mode 授权；证据链未闭合。"
    elif repo == "openharmony/systemabilitymgr_safwk":
        finding = "StartAbilityInner 有输入校验，但本地/远程调用者 privilege boundary 和上游 ability policy 未完整绑定。"
    else:
        finding = "未建立完整授权 guard dominance。"
    scope = "out_of_scope_test_code" if "test/" in file else "production_ipc_auth_policy_incomplete"
    return {
        "review_scope": scope,
        "guard_dominance": {"status": "partial" if scope != "out_of_scope_test_code" else "not_applicable", "finding": finding},
        "ownership_atomicity": {"status": "not_applicable", "finding": "授权候选不以共享对象原子性为核心证明。"},
        "entry_privilege_boundary": {"status": "partial" if scope != "out_of_scope_test_code" else "out_of_scope", "finding": finding},
        "reachable_sensitive_operation": {"status": "not_established", "finding": "未证明无授权调用者可到达被保护的敏感操作。"},
        "attacker_controlled_trigger": {"status": "partial", "finding": "IPC 参数可能可控，但调用者权限域与绕过条件未证明。"},
        "cia_impact": {"status": "not_established", "finding": "未证明具体 CIA 影响。"},
    }


def static_relay(_: dict) -> dict:
    return {
        "review_scope": "normal_priority_descriptor_boundary_candidate",
        "guard_dominance": {"status": "not_established", "finding": "本轮仅核验源码绑定；未形成 descriptor 边界 guard dominance 的完整数据流。"},
        "ownership_atomicity": {"status": "not_established", "finding": "未绑定目标缓冲区容量和跨函数所有权。"},
        "entry_privilege_boundary": {"status": "not_established", "finding": "普通优先级候选未完成入口权限建模。"},
        "reachable_sensitive_operation": {"status": "not_established", "finding": "未证明越界数据流到达敏感操作。"},
        "attacker_controlled_trigger": {"status": "not_established", "finding": "未证明可控长度/描述符可稳定触发。"},
        "cia_impact": {"status": "not_established", "finding": "未证明具体 CIA 影响。"},
    }


def dynamic_and_status(diagnostic: dict, binding: dict) -> tuple[dict, str, list[str]]:
    rule = diagnostic["rule_id"]
    repo = diagnostic["repository"]
    file = diagnostic["file"]
    if rule == "ohcpp-shared-ptr-race-candidate-001":
        return (
            {
                "target_derived": False,
                "result": "not_run_target_derived_harness",
                "method_controls": "generic_tsan_positive_control_detected_race_and_atomic_fixed_control_clean_3_replays",
                "sandbox_image": SANDBOX_IMAGE,
                "interpretation": "通用 TSan 控制只证明方法可用，不证明抽样组件存在数据竞争。",
            },
            "not_testable",
            obligations_shared_ptr(),
        )
    if rule == "ipc.parcel.copy-range":
        return (
            {
                "target_derived": True,
                "result": "source_derived_reduced_model_no_asan_ubsan_finding",
                "method_controls": "bounded_model_clean_3_replays; unsafe_oob_positive_control_detected_3_replays; safe_control_clean_3_replays",
                "sandbox_image": SANDBOX_IMAGE,
                "interpretation": "缩约源码模型复核 guard 与拷贝容量；不等同完整产品构建 PoC。",
            },
            "not_reproduced",
            obligations_copy_range(),
        )
    if rule == "ipc.capability.export":
        test_only = "test/unittest" in file or "test/services" in file
        guarded_samgr = repo == "openharmony/systemabilitymgr_samgr" and not test_only
        status = "not_reproduced" if guarded_samgr else "not_testable"
        result = "not_run_target_derived_harness; static_guard_dominance_review" if guarded_samgr else "not_run_target_derived_harness; policy/context incomplete"
        return (
            {
                "target_derived": False,
                "result": result,
                "method_controls": "no target-derived runnable harness; generic sanitizer controls are not substitutes",
                "sandbox_image": SANDBOX_IMAGE,
                "interpretation": "未满足产品入口、权限边界和 CIA 影响证据门。",
            },
            status,
            obligations_capability(),
        )
    if rule in ("ipc.auth.missing", "ipc.auth.guard-coverage"):
        return (
            {
                "target_derived": False,
                "result": "not_run_target_derived_harness; authorization_policy_not_closed",
                "method_controls": "no target-derived runnable harness; generic sanitizer controls are not substitutes",
                "sandbox_image": SANDBOX_IMAGE,
                "interpretation": "局部未识别 guard 不等于真实授权缺失。",
            },
            "not_testable",
            obligations_ipc_auth(),
        )
    return (
        {
            "target_derived": False,
            "result": "not_run_target_derived_harness; normal_priority_not_in_focus_poc_queue",
            "method_controls": "none",
            "sandbox_image": SANDBOX_IMAGE,
            "interpretation": "普通优先级候选保留为待验证项，不进入本轮重点 PoC 队列。",
        },
        "not_testable",
        obligations_relay(),
    )


def main() -> None:
    manifest = load("sample_manifest.json")
    provenance = load("provenance.json")
    checks = {
        item["diagnostic_id"]: item
        for record in provenance["records"]
        for item in record.get("source_checks", [])
    }
    records = []
    index = 1
    for sample in manifest["records"]:
        for diagnostic in sample["diagnostics"]:
            check = checks.get(diagnostic["diagnostic_id"], {})
            binding = source_binding(diagnostic["diagnostic_id"], check, diagnostic)
            rule = diagnostic["rule_id"]
            if rule == "ohcpp-shared-ptr-race-candidate-001":
                static = static_shared_ptr(diagnostic)
            elif rule == "ipc.parcel.copy-range":
                static = static_copy_range(diagnostic)
            elif rule == "ipc.capability.export":
                static = static_capability({**diagnostic, "repository": sample["repository"]})
            elif rule in ("ipc.auth.missing", "ipc.auth.guard-coverage"):
                static = static_auth({**diagnostic, "repository": sample["repository"]})
            else:
                static = static_relay(diagnostic)
            dynamic, status, remaining = dynamic_and_status(
                {**diagnostic, "repository": sample["repository"]}, binding
            )
            records.append({
                "review_id": f"CR-{index:04d}",
                "sample_order": sample["sample_order"],
                "repository": sample["repository"],
                "library": sample["repository"].split("/", 1)[-1],
                "commit": sample["commit"],
                "git_tree": sample["git_tree"],
                "snapshot_sha256": sample["snapshot_sha256"],
                "scanner_provider": diagnostic.get("provider"),
                "detector_version": diagnostic.get("detector_version"),
                "diagnostic_id": diagnostic.get("diagnostic_id"),
                "rule_id": rule,
                "candidate_cwe": diagnostic.get("candidate_cwe"),
                "consequence_cwe": diagnostic.get("consequence_cwe"),
                "severity_reported": diagnostic.get("severity"),
                "risk_priority": "high" if rule != "ipc.relay.descriptor-boundary" else "normal",
                "high_risk_candidate": rule != "ipc.relay.descriptor-boundary",
                "file": diagnostic.get("file"),
                "line": diagnostic.get("line"),
                "column": diagnostic.get("column"),
                "symbol": diagnostic.get("symbol"),
                "source_binding": binding,
                "static_review": static,
                "dynamic_validation": dynamic,
                "remaining_proof_obligations": remaining,
                "final_status": status,
                "poc": {"status": "none", "reason": "未通过 confirmed/reportable 完整证据门，禁止生成漏洞 PoC。"},
            })
            index += 1
    status_counts = Counter(row["final_status"] for row in records)
    rule_counts = Counter(row["rule_id"] for row in records)
    high_status_counts = Counter(row["final_status"] for row in records if row["high_risk_candidate"])
    summary = {
        "schema_version": "candidate-reviews-v1",
        "created_at": "2026-10-18T12:00:00+08:00",
        "reviewed_candidates": len(records),
        "high_priority_candidates": sum(row["high_risk_candidate"] for row in records),
        "normal_priority_candidates": sum(not row["high_risk_candidate"] for row in records),
        "confirmed_vulnerabilities": 0,
        "dedicated_pocs": 0,
        "status_counts": dict(sorted(status_counts.items())),
        "high_priority_status_counts": dict(sorted(high_status_counts.items())),
        "rule_counts": dict(sorted(rule_counts.items())),
        "evidence_gate": "confirmed requires realistic entry/privilege boundary, reachable sensitive operation, attacker-controlled trigger, and concrete CIA impact.",
        "records": records,
    }
    (EVIDENCE / "candidate_reviews.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    print(json.dumps({key: summary[key] for key in summary if key != "records"}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
