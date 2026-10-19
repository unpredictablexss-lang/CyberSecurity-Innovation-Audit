#!/usr/bin/env python3
"""Run one candidate -> isolated component PoC -> report-fragment evidence loop."""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from typing import Any


ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.poc import reachability  # noqa: E402
from src.ohscanner.poc.runner import SANITIZER_MARKERS  # noqa: E402
from src.workbench import validation  # noqa: E402
from src.workbench.settings import Settings  # noqa: E402


REPO = "openharmony/inputmethod_imf"
VULNERABLE = "e663b47013d534a56165ab7467fbb3e14bf7172b"
FIXED = "5eaddcab19bc4b22544f4bee1e8894fc2d6505dc"
CUTILS_REPO = "openharmony/commonlibrary_c_utils"
CANDIDATE_ID = "ohscanner.interface.ipc:c590c70a85c68412"
DETECTOR_VERSION = "0.5.0"
SOURCE_SHA = "59c980bf8923fe783ab1f02ac9d999b6eb0c6a3fbcf62a16b369000b5877e043"
SOURCE_PATH = "services/src/platform_callback_stub.cpp"
RULE = "ipc.relay.descriptor-boundary"
SYMBOL = "PlatformCallbackStub::OnRemoteRequest"


def now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def git(repo: Path, *args: str) -> bytes:
    done = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=False)
    if done.returncode:
        raise RuntimeError(done.stderr.decode("utf-8", "replace")[-1000:])
    return done.stdout


def git_text(repo: Path, *args: str) -> str:
    return git(repo, *args).decode("utf-8", "replace").strip()


def recorded(argv: list[str], logs: Path, name: str) -> dict[str, Any]:
    logs.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    done = subprocess.run(argv, cwd=str(ROOT), capture_output=True, check=False)
    out, err = logs / f"{name}.stdout.log", logs / f"{name}.stderr.log"
    out.write_bytes(done.stdout)
    err.write_bytes(done.stderr)
    return {
        "argv": argv,
        "cwd": str(ROOT),
        "returncode": done.returncode,
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "stdout_sha256": sha(out),
        "stderr_sha256": sha(err),
    }


def checkout_identity() -> dict[str, Any]:
    return {
        "branch": git_text(ROOT, "branch", "--show-current"),
        "head": git_text(ROOT, "rev-parse", "HEAD"),
        "tree": git_text(ROOT, "rev-parse", "HEAD^{tree}"),
        "remote": git_text(ROOT, "remote", "get-url", "origin"),
        "status_short": git_text(ROOT, "status", "--short", "--branch").splitlines(),
    }


def verify_sources(target: Path, cutils: Path, manifest: dict[str, Any]) -> dict[str, Any]:
    rows = []
    for kind, entries in (("source", manifest["sources"]), ("header", manifest["headers"])):
        for item in entries:
            raw = git(target, "cat-file", "blob", f"{item['commit']}:{item['path']}")
            actual = hashlib.sha256(raw).hexdigest()
            if actual != item["sha256"]:
                raise ValueError(f"source hash mismatch: {item['path']}")
            rows.append({"kind": kind, **item, "actual_sha256": actual, "bytes": len(raw)})
    return {
        "target_repository": REPO,
        "target_head": git_text(target, "rev-parse", "HEAD"),
        "target_revisions": {
            item: {
                "commit": git_text(target, "rev-parse", f"{item}^{{commit}}"),
                "tree": git_text(target, "rev-parse", f"{item}^{{tree}}"),
            }
            for item in (VULNERABLE, FIXED)
        },
        "cutils_repository": CUTILS_REPO,
        "cutils_head": git_text(cutils, "rev-parse", "HEAD"),
        "files": rows,
    }


def static_scan(output: Path, target: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    static = output / "static"
    static.mkdir(parents=True, exist_ok=False)
    json_path, md_path = static / "detector-report.json", static / "detector-report.md"
    argv = [
        sys.executable, "-m", "src.cli.main", "ohscan-run",
        "--repo-dir", str(target), "--repository", REPO, "--commit", VULNERABLE,
        "--include", "services", "--detector", "ohscanner.interface.ipc",
        "--json-out", str(json_path.relative_to(ROOT)),
        "--md-out", str(md_path.relative_to(ROOT)),
    ]
    command = recorded(argv, output / "logs", "static-scan")
    if command["returncode"]:
        raise RuntimeError("static detector scan failed")
    report = json.loads(json_path.read_text(encoding="utf-8"))
    runs = report["detector_runs"]
    if len(runs) != 1 or runs[0]["tool_version"] != DETECTOR_VERSION:
        raise ValueError("detector identity/version changed; freeze a new sample")
    matches = [
        row for row in runs[0]["diagnostics"]
        if row["file"] == SOURCE_PATH and row["rule_id"] == RULE
        and row.get("symbol") == SYMBOL and row.get("source_sha256") == SOURCE_SHA
    ]
    if len(matches) != 1 or matches[0]["diagnostic_id"] != CANDIDATE_ID:
        raise ValueError("candidate identity changed; freeze a new sample")
    obligations = [
        item["obligations"]
        for coverage in report["detector_coverage"]["detectors"].values()
        for item in coverage.get("evidence_obligations", [])
        if item["diagnostic_id"] == CANDIDATE_ID
    ][0]
    command.update({
        "json_report_sha256": sha(json_path),
        "markdown_report_sha256": sha(md_path),
    })
    return {"report": report, "candidate": matches[0], "obligations": obligations}, command


def checklist(output: Path, bundle: dict[str, Any], source: dict[str, Any], reach: dict[str, Any]) -> Path:
    candidate = bundle["candidate"]
    lines = [
        "# AUTH-01 最小 PoC 闭环：人工复核检查清单",
        "",
        "> 执行前清单。机器证据不能替代产品入口、权限边界、攻击者控制和 CIA 影响的人工签收。",
        f"- 候选：`{candidate['diagnostic_id']}`；状态 `candidate / possible_hit / unassessed`。",
        f"- 目标：`{REPO}` @ `{VULNERABLE}`；`{candidate['file']}:{candidate['line']}`。",
        f"- source SHA-256：`{candidate['source_sha256']}`；历史根因绑定 `CVE-2023-0036`。",
        "",
        "## EvidenceObligation",
        "",
        "| kind | 初始状态 | 人工复核重点 |",
        "|---|---|---|",
    ]
    focus = {
        "entry_reachability": "真实入口、句柄获取、调用者身份和权限边界",
        "callee_and_policy": "接收者绑定、权限策略和上游守卫",
        "security_impact": "攻击者控制、触发条件和具体 CIA 后果",
        "consequence": "实际暴露的数据、能力、状态和对象",
    }
    for item in bundle["obligations"]:
        lines.append(f"| `{item['kind']}` | `{item['status']}` | {focus[item['kind']]} |")
    lines += [
        "",
        "## 检查步骤",
        "",
        "- [x] 固定 commit/tree/blob/source SHA 已重新核验。",
        "- [x] Detector 候选和 EvidenceObligation 已绑定；没有自动确认。",
        "- [ ] 逐条核验 `manifest.reachability.relations` 的引文和未证明项。",
        "- [ ] 核验 CVE/公告/补丁来源，而不是凭名称关联。",
        "- [ ] 判断未特权/无关进程能否取得 callback 句柄及真实调用身份。",
        "- [ ] 把组件消息投递映射到真实产品 CIA 影响。",
        "- [ ] 审阅 vulnerable/fixed/patched、正负控制和稳定重放。",
        "- [ ] 人工签收继续保持候选状态，或给出满足证据门的升级依据。",
        "",
        "## 固定证据入口",
        "",
        "- `static/detector-report.json`、`static/detector-report.md`",
        "- `source-verification.json`、`reachability-verification.json`",
        "- `runtime/validation-command.json`、`runtime/input-manifest.json`",
        "- `runtime/docker.log`、`runtime/validation-result.json`",
        "",
        f"目标仓库本地 HEAD `{source['target_head']}`；可达性机器核验 `{reach['status']}`。",
    ]
    path = output / "manual-review-checklist.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


class DirectoryOps:
    def __init__(self, path: Path, task_id: str):
        self.path, self.task_id = path, task_id

    def directory(self, key: str) -> Path:
        if key != self.task_id:
            raise ValueError("unexpected operation id")
        self.path.mkdir(parents=True, exist_ok=True)
        return self.path


def isolated_validation(output: Path, target: Path, cutils: Path, image: str, case_id: str):
    if os.name != "posix":
        raise RuntimeError("run inside Ubuntu WSL")
    os.environ["OHSCANNER_VALIDATION_IMAGE"] = image
    ready = validation.readiness()
    if not ready["ready"]:
        raise RuntimeError(ready["reason"])
    task_id = hashlib.sha256(f"AUTH-01|minimal-loop|{VULNERABLE}|{case_id}".encode()).hexdigest()[:32]
    task = {
        "id": task_id,
        "kind": "validation",
        "spec": {
            "case_id": case_id,
            "harness_id": "auth01_descriptor_bypass",
            "target_repository_id": "target",
            "target_repository": REPO,
            "target_commit": VULNERABLE,
            "target_path": str(target),
            "cutils_repository_id": "cutils",
            "cutils_repository": CUTILS_REPO,
            "cutils_commit": git_text(cutils, "rev-parse", "HEAD"),
            "cutils_path": str(cutils),
            "repeats": 3,
            "timeout_seconds": 900,
            "memory_mb": 2048,
        },
    }
    settings = Settings(output / "workbench-data", (target.parent.resolve(), cutils.parent.resolve()))
    result = validation.execute_validation(settings, None, DirectoryOps(output / "runtime", task_id), task)
    write_json(output / "runtime/execute-validation-envelope.json", result)
    return result, {"task": task, "readiness": ready}


def behavior(result: dict[str, Any]) -> dict[str, Any]:
    poc = result["result"]
    rows = []
    for revision in ("vulnerable", "fixed", "patched"):
        run = poc["revisions"][revision]
        cases = {item["case_id"]: item for item in run["cases"]}
        replays = {item["case_id"]: item for item in run["replay"]["cases"]}
        for case_id in ("no_token", "correct_token", "foreign_token"):
            case = cases[case_id]
            replay = replays.get(case_id)
            rows.append({
                "revision": revision,
                "commit": run["commit"],
                "case_id": case_id,
                "role": case["role"],
                "verdict": case["verdict"],
                "signals": case["signals"],
                "expected": replay["expected"] if replay else "any",
                "observed_replays": replay["observed"] if replay else [],
                "matches_expectation": replay["matches_expectation"] if replay else [],
                "label": replay["label"] if replay else "not_replayed",
            })
    text = json.dumps(poc, ensure_ascii=False)
    return {
        "rows": rows,
        "sanitizers_enabled": poc["environment"]["sanitizers"],
        "sanitizer_report_markers_detected": [x for x in SANITIZER_MARKERS if x in text],
        "observable": "messages_sent and parsed message fields printed by the harness",
    }


def assert_gate(result: dict[str, Any], matrix: dict[str, Any]) -> None:
    if result["status"] != "completed_with_limitations" or result["validation_gate"] != "passed":
        raise ValueError("component validation gate did not pass")
    poc = result["result"]
    if result["validated_vulnerability"] != 0 or poc["validated_vulnerability"] != 0:
        raise ValueError("validated vulnerability must remain zero")
    if poc["state"] != "stable_reproduced" or poc["evidence_level"] != "stable_reproduced":
        raise ValueError("vulnerable component case was not stable")
    if poc["reachability"]["status"] != "partial":
        raise ValueError("product reachability must remain partial")
    rows = {(x["revision"], x["case_id"]): x for x in matrix["rows"]}
    expected = {
        ("vulnerable", "no_token"): "trigger",
        ("fixed", "no_token"): "no_trigger",
        ("patched", "no_token"): "no_trigger",
        ("fixed", "correct_token"): "trigger",
    }
    for key, verdict in expected.items():
        if rows[key]["verdict"] != verdict:
            raise ValueError(f"unexpected behavior for {key}")
    if matrix["sanitizer_report_markers_detected"]:
        raise ValueError("sanitizer markers appeared; freeze a new sample")


def runtime_hashes(output: Path) -> dict[str, Any]:
    names = [
        "input-manifest.json", "validation-command.json", "validation-result.json",
        "execute-validation-envelope.json", "docker.log", "poc/auth01-manifest.json",
        "poc/auth01-upstream-fix.patch", "poc/poc/bin/poc_vulnerable",
        "poc/poc/bin/poc_fixed", "poc/poc/bin/poc_patched",
    ]
    return {
        name: {"sha256": sha(output / "runtime" / name), "bytes": (output / "runtime" / name).stat().st_size}
        for name in names
    }


def disposition(output: Path, check: Path, bundle: dict[str, Any], result: dict[str, Any], matrix: dict[str, Any]) -> Path:
    poc = result["result"]
    record = {
        "schema_version": 1,
        "created_at_utc": now(),
        "candidate_id": bundle["candidate"]["diagnostic_id"],
        "state": {
            "candidate_status": "candidate",
            "triage_status": "possible_hit",
            "vulnerability_assessment": "unassessed",
            "validated_vulnerability": 0,
            "reportable": False,
        },
        "manual_checklist": {
            "path": str(check.relative_to(ROOT)),
            "sha256": sha(check),
            "human_signoff": "pending",
        },
        "machine_evidence": {
            "source_binding": "satisfied",
            "detector_candidate": "satisfied",
            "component_behavior_difference": "satisfied",
            "fixed_control": "satisfied",
            "patch_replay": "satisfied",
            "stability_replay": "satisfied",
            "sanitizer_execution": "enabled",
            "product_entry_reachability": poc["reachability"]["status"],
            "permission_and_caller_identity": "unknown",
            "concrete_cia_impact": "unknown",
        },
        "evidence_obligations": bundle["obligations"],
        "behavior_matrix": matrix,
        "limitations": result["limitations"],
    }
    path = output / "review-disposition.json"
    write_json(path, record)
    return path


def evidence_record(
    output: Path,
    identity: dict[str, Any],
    source_path: Path,
    reach_path: Path,
    check_path: Path,
    command: dict[str, Any],
    bundle: dict[str, Any],
    result: dict[str, Any],
    context: dict[str, Any],
    matrix: dict[str, Any],
    disposition_path: Path,
) -> Path:
    record = {
        "schema_version": 1,
        "created_at_utc": now(),
        "loop_kind": "candidate_to_isolated_component_poc_to_report_fragment",
        "state": {
            "candidate_status": "candidate",
            "triage_status": "possible_hit",
            "vulnerability_assessment": "unassessed",
            "validated_vulnerability": 0,
            "reportable": False,
        },
        "project_checkout": identity,
        "source_binding": json.loads(source_path.read_text(encoding="utf-8")),
        "detector_candidate": bundle["candidate"],
        "evidence_obligations": bundle["obligations"],
        "commands": {
            "static_scan": command,
            "validation_command_record": "runtime/validation-command.json",
            "validation_input_manifest": "runtime/input-manifest.json",
        },
        "manual_review": {
            "checklist_path": str(check_path.relative_to(ROOT)),
            "checklist_sha256": sha(check_path),
            "disposition_path": str(disposition_path.relative_to(ROOT)),
            "disposition_sha256": sha(disposition_path),
            "human_signoff": "pending",
        },
        "reachability": json.loads(reach_path.read_text(encoding="utf-8")),
        "runtime_validation": {
            "status": result["status"],
            "validation_gate": result["validation_gate"],
            "gate_reason": result["gate_reason"],
            "validated_vulnerability": result["validated_vulnerability"],
            "patched_revision": result["patched_revision"],
            "poc_state": result["result"]["state"],
            "poc_evidence_level": result["result"]["evidence_level"],
            "environment": result["result"]["environment"],
            "behavior": matrix,
            "isolation": context["readiness"],
            "artifacts": runtime_hashes(output),
        },
        "limitations": result["limitations"],
    }
    path = output / "evidence-record.json"
    write_json(path, record)
    return path


def report_fragment(output: Path, bundle: dict[str, Any], result: dict[str, Any], matrix: dict[str, Any], evidence_path: Path) -> Path:
    candidate = bundle["candidate"]
    poc = result["result"]
    rows = {(x["revision"], x["case_id"]): x for x in matrix["rows"]}
    lines = [
        "# 报告片段：AUTH-01 descriptor-boundary 候选最小闭环",
        "",
        "> 状态：`candidate / possible_hit / unassessed`；确认漏洞数 0；不可直接作为 reportable。",
        "",
        "## 1. 候选与来源绑定",
        "",
        f"- 候选：`{candidate['diagnostic_id']}`；`{candidate['provider']}` `{DETECTOR_VERSION}`。",
        f"- 目标：`{REPO}` @ `{VULNERABLE}`；`{candidate['file']}:{candidate['line']}`。",
        f"- 符号：`{candidate['symbol']}`；规则 `{candidate['rule_id']}`。",
        f"- source SHA-256：`{candidate['source_sha256']}`；候选 CWE `{candidate['candidate_cwe']}`。",
        "- 历史根因绑定 `CVE-2023-0036` / `OpenHarmony-SA-2023-0102`；不产生新 CVE 结论。",
        "",
        "## 2. EvidenceObligation",
        "",
        "| obligation | 初始 | 当前证据 | 仍未知 |",
        "|---|---|---|---|",
    ]
    current = {
        "entry_reachability": ("服务构造并远程传递 stub 的关系已逐 blob/行号核验", "句柄获取、真实入口和调用身份"),
        "callee_and_policy": ("组件 Harness 验证 descriptor 校验前后差异", "产品构建、权限和接收者策略"),
        "security_impact": ("vulnerable 无 token 触发；fixed/patched 拒绝", "真实产品 CIA 影响"),
        "consequence": ("观测 messages_sent 和 payload 字段", "实际暴露对象与范围"),
    }
    for item in bundle["obligations"]:
        yes, no = current[item["kind"]]
        lines.append(f"| `{item['kind']}` | `{item['status']}` | {yes} | {no} |")
    lines += [
        "",
        "## 3. 本地隔离 PoC 行为差异",
        "",
        f"- 隔离：`{os.environ.get('OHSCANNER_VALIDATION_IMAGE')}`；无网络、去 capabilities、只读根目录、资源限制。",
        f"- Sanitizer：`{', '.join(matrix['sanitizers_enabled'])}`；主证据为受控行为差异。",
        f"- 组件生命周期 `{poc['state']}`；组件证据等级 `{poc['evidence_level']}`；攻击/预期控制用例稳定重放 3 次，`expect=any` 探索用例不重复。",
        "",
        "| 修订 | commit | no_token | correct_token | foreign_token | label |",
        "|---|---|---|---|---|---|",
    ]
    for revision, commit in (("vulnerable", VULNERABLE), ("fixed", FIXED), ("patched", result["patched_revision"]["synthetic_commit"])):
        lines.append(
            f"| {revision} | `{commit}` | {rows[(revision, 'no_token')]['verdict']} | "
            f"{rows[(revision, 'correct_token')]['verdict']} | {rows[(revision, 'foreign_token')]['verdict']} | "
            f"{rows[(revision, 'no_token')]['label']} |"
        )
    lines += [
        "",
        "关键差异：vulnerable 的 `no_token` 触发；fixed 和 patch replay 均拒绝；",
        "fixed 的 `correct_token` 仍触发，说明不是整体功能失效。",
        "",
        "## 4. 证据记录",
        "",
        f"- `evidence-record.json` SHA-256 `{sha(evidence_path)}`",
        "- `manual-review-checklist.md`、`static/detector-report.json`",
        "- `runtime/validation-command.json`、`runtime/input-manifest.json`",
        "- `runtime/docker.log`、`runtime/validation-result.json`",
        f"- patch SHA-256 `{result['patched_revision']['patch_sha256']}`",
        "",
        "## 5. 结论边界",
        "",
        "- 可写：组件级 descriptor-boundary 行为差异已在本地隔离环境稳定复现，修复与补丁重验拒绝攻击用例。",
        "- 不可写：真实产品可利用、已确认漏洞、新 CVE、影响版本或 reportable。",
        "- 状态保持 `candidate / possible_hit / unassessed`；产品入口、权限/身份和 CIA 影响仍未知。",
    ]
    path = output / "report-fragment.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def artifact_manifest(output: Path, evidence: Path, report: Path) -> Path:
    paths = [
        output / "source-verification.json", output / "reachability-verification.json",
        output / "manual-review-checklist.md", output / "review-disposition.json",
        evidence, report, output / "static/detector-report.json", output / "static/detector-report.md",
        output / "runtime/input-manifest.json", output / "runtime/validation-command.json",
        output / "runtime/validation-result.json", output / "runtime/execute-validation-envelope.json",
        output / "runtime/docker.log", output / "runtime/poc/auth01-upstream-fix.patch",
    ]
    record = {
        "schema_version": 1,
        "created_at_utc": now(),
        "files": {
            str(path.relative_to(ROOT)): {"sha256": sha(path), "bytes": path.stat().st_size}
            for path in paths
        },
    }
    path = output / "artifact-manifest.json"
    write_json(path, record)
    return path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", type=Path, default=Path("/home/audit/openharmony-audit/ipc-research/repos/inputmethod_imf"))
    parser.add_argument("--cutils", type=Path, default=Path("/home/audit/openharmony-targets/commonlibrary_c_utils"))
    parser.add_argument("--docker-image", default="ohscanner-validation@sha256:da2be0997cf04e71a80f35c312976bc3ba96399757563f01816f011ef25c12dc")
    parser.add_argument("--output", type=Path, default=ROOT / "outputs/poc-loop/auth01-20261014/run-001")
    parser.add_argument("--case-id", default="auth01-minimal-loop-20261014")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output = args.output.resolve()
    if output.exists() and any(output.iterdir()):
        raise RuntimeError(f"refusing to overwrite non-empty evidence directory: {output}")
    output.mkdir(parents=True, exist_ok=True)
    target, cutils = args.target.resolve(strict=True), args.cutils.resolve(strict=True)
    manifest_path = ROOT / "src/ohscanner/poc/harnesses/auth01_descriptor_bypass/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    identity = checkout_identity()
    source_path = output / "source-verification.json"
    write_json(source_path, verify_sources(target, cutils, manifest))
    reach_path = output / "reachability-verification.json"
    write_json(reach_path, dataclasses.asdict(reachability.verify(manifest["reachability"], target)))
    bundle, command = static_scan(output, target)
    check_path = checklist(
        output, bundle,
        json.loads(source_path.read_text(encoding="utf-8")),
        json.loads(reach_path.read_text(encoding="utf-8")),
    )
    result, context = isolated_validation(output, target, cutils, args.docker_image, args.case_id)
    matrix = behavior(result)
    assert_gate(result, matrix)
    disposition_path = disposition(output, check_path, bundle, result, matrix)
    evidence_path = evidence_record(
        output, identity, source_path, reach_path, check_path, command,
        bundle, result, context, matrix, disposition_path,
    )
    report_path = report_fragment(output, bundle, result, matrix, evidence_path)
    manifest_out = artifact_manifest(output, evidence_path, report_path)
    summary = {
        "status": "completed_with_limitations",
        "candidate_status": "candidate",
        "triage_status": "possible_hit",
        "vulnerability_assessment": "unassessed",
        "validated_vulnerability": 0,
        "candidate_id": bundle["candidate"]["diagnostic_id"],
        "validation_gate": result["validation_gate"],
        "report_fragment_sha256": sha(report_path),
        "evidence_record_sha256": sha(evidence_path),
        "artifact_manifest_sha256": sha(manifest_out),
    }
    write_json(output / "run-summary.json", summary)
    print(json.dumps(summary, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
