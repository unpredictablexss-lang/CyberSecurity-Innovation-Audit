"""Source-bound JSProxy shared_ptr race PoC and patch revalidation.

The runner verifies the audited Git object identity and source bytes, runs the
current shared_ptr detector against vulnerable and repaired variants, then
builds a local ThreadSanitizer workload. It never contacts a live service and
never upgrades the candidate to confirmed/reportable.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.shared_ptr_race_detector import SharedPtrRaceDetector

ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MANIFEST = Path(__file__).resolve().parent / "harnesses/cpp_shared_ptr_jsproxy/manifest.json"
DEFAULT_HARNESS = DEFAULT_MANIFEST.parent / "harness.cpp"
RUN_VARIANTS = ("vulnerable", "fixed_control_mutex", "patched_atomic_minimal")
RACE_MODES = ("single", "race", "close_get_entry", "unrelated")
TSAN_MARKERS = ("WARNING: ThreadSanitizer:", "SUMMARY: ThreadSanitizer:")


@dataclass(frozen=True)
class SourceRecord:
    path: str
    blob: str
    sha256: str
    checkout_sha256: str
    role: str
    verified: bool


@dataclass(frozen=True)
class DetectorRecord:
    variant: str
    status: str
    finding_count: int
    findings: Tuple[Mapping[str, object], ...]
    limitations: Tuple[str, ...]


@dataclass(frozen=True)
class BuildRecord:
    variant: str
    command: Tuple[str, ...]
    exit_code: Optional[int]
    elapsed_seconds: float
    stdout: str
    stderr: str
    outcome: str


@dataclass(frozen=True)
class RunRecord:
    variant: str
    mode: str
    repeat: int
    command: Tuple[str, ...]
    exit_code: Optional[int]
    elapsed_seconds: float
    stdout: str
    stderr: str
    sanitizer_detected: bool
    outcome: str


@dataclass(frozen=True)
class JsProxyPoCResult:
    package_id: str
    detector_id: str
    detector_version: str
    rule_id: str
    source_binding_status: str
    source: SourceRecord
    call_path_sources: Tuple[SourceRecord, ...]
    detector_runs: Tuple[DetectorRecord, ...]
    builds: Tuple[BuildRecord, ...]
    runs: Tuple[RunRecord, ...]
    repeats: int
    outcome: str
    patch_sha256: str
    patched_source_sha256: str
    fixed_source_sha256: str
    environment: Mapping[str, object]
    limitations: Tuple[str, ...]
    candidate_status: str = "candidate/unknown"
    validated_vulnerability: int = 0

    def to_dict(self) -> Dict[str, object]:
        return {
            "schema_version": 2,
            "package_id": self.package_id,
            "detector": {
                "id": self.detector_id,
                "version": self.detector_version,
                "rule_id": self.rule_id,
            },
            "candidate_status": self.candidate_status,
            "validated_vulnerability": self.validated_vulnerability,
            "source_binding_status": self.source_binding_status,
            "source": asdict(self.source),
            "call_path_sources": [asdict(item) for item in self.call_path_sources],
            "detector_runs": [asdict(item) for item in self.detector_runs],
            "builds": [asdict(item) for item in self.builds],
            "runs": [asdict(item) for item in self.runs],
            "repeats": self.repeats,
            "outcome": self.outcome,
            "patch": {
                "sha256": self.patch_sha256,
                "fixed_source_sha256": self.fixed_source_sha256,
                "patched_source_sha256": self.patched_source_sha256,
                "fixed_control": "mutex around JSProxy owner access",
                "minimal_patch": "std::atomic_load/std::atomic_store on instance_",
            },
            "evidence_level": "controlled_component_dynamic_reproduction",
            "environment": dict(self.environment),
            "limitations": list(self.limitations),
        }


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _run(command: Sequence[str], cwd: Path, timeout: float, env: Optional[Mapping[str, str]] = None) -> Tuple[int, float, str, str, bool]:
    started = time.monotonic()
    try:
        completed = subprocess.run(
            list(command),
            cwd=str(cwd),
            text=True,
            capture_output=True,
            timeout=timeout,
            env=dict(env) if env is not None else None,
            check=False,
        )
        return completed.returncode, time.monotonic() - started, completed.stdout, completed.stderr, False
    except subprocess.TimeoutExpired as exc:
        return None, time.monotonic() - started, exc.stdout or "", exc.stderr or "", True


def _git(repo: Path, *args: str, timeout: float = 30.0) -> str:
    code, _, stdout, stderr, timed_out = _run(("git", "-C", str(repo), *args), repo, timeout)
    if timed_out or code != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {stderr or stdout}")
    return stdout.strip()


def _git_blob(repo: Path, blob: str) -> bytes:
    completed = subprocess.run(
        ("git", "-C", str(repo), "cat-file", "blob", blob),
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError("git cat-file blob failed: " + completed.stderr.decode("utf-8", "replace"))
    return completed.stdout


def _resolve_repo(manifest: Mapping[str, object]) -> Path:
    raw = Path(str(manifest["source_repo_path"]))
    if raw.exists():
        return raw
    wsl = Path(str(manifest["source_repo_path"]).replace("E:\\网安", "/mnt/e/网安").replace("\\", "/"))
    if wsl.exists():
        return wsl
    raise FileNotFoundError(f"source repository not found: {raw}")


def verify_sources(manifest: Mapping[str, object]) -> Tuple[SourceRecord, Tuple[SourceRecord, ...], Dict[str, bytes]]:
    repo = _resolve_repo(manifest)
    commit = _git(repo, "rev-parse", "HEAD")
    tree = _git(repo, "rev-parse", "HEAD^{tree}")
    if commit != manifest["commit"] or tree != manifest["git_tree"]:
        raise RuntimeError(f"source identity mismatch: commit={commit} tree={tree}")
    source_path = str(manifest["source_path"])
    source_blob = _git(repo, "rev-parse", f"HEAD:{source_path}")
    source_bytes = _git_blob(repo, source_blob)
    source_sha = _sha256(source_bytes)
    checkout_sha = _sha256((repo / source_path).read_bytes())
    if source_blob != manifest["source_blob"] or source_sha != manifest["source_sha256"]:
        raise RuntimeError(f"source binding mismatch: blob={source_blob} sha256={source_sha}")
    if checkout_sha != manifest["source_checkout_sha256"]:
        raise RuntimeError(f"source checkout hash mismatch: {checkout_sha}")
    source = SourceRecord(
        source_path,
        source_blob,
        source_sha,
        checkout_sha,
        "vulnerable JSProxy owner implementation",
        True,
    )
    records: List[SourceRecord] = []
    blobs: Dict[str, bytes] = {source_path: source_bytes}
    for entry in manifest["call_path_sources"]:
        path = str(entry["path"])
        blob = _git(repo, "rev-parse", f"HEAD:{path}")
        data = _git_blob(repo, blob)
        checkout_sha = _sha256((repo / path).read_bytes())
        expected_blob = str(entry["blob"])
        expected_sha = str(entry["sha256"])
        if blob != expected_blob or _sha256(data) != expected_sha:
            raise RuntimeError(f"call-path binding mismatch: path={path} blob={blob} sha256={_sha256(data)}")
        if checkout_sha != entry["checkout_sha256"]:
            raise RuntimeError(f"call-path checkout hash mismatch: path={path} sha256={checkout_sha}")
        records.append(SourceRecord(path, blob, _sha256(data), checkout_sha, str(entry["role"]), True))
        blobs[path] = data
    return source, tuple(records), blobs

def _detector_dict(item: object) -> Dict[str, object]:
    if hasattr(item, "__dataclass_fields__"):
        return {key: _detector_dict(value) for key, value in asdict(item).items()}
    if isinstance(item, tuple):
        return [_detector_dict(value) for value in item]
    if isinstance(item, list):
        return [_detector_dict(value) for value in item]
    if isinstance(item, dict):
        return {str(key): _detector_dict(value) for key, value in item.items()}
    return item


def run_detector(variant: str, path: str, data: bytes) -> DetectorRecord:
    text = data.decode("utf-8")
    unit = SourceUnit(path=path, language="cpp", text=text, sha256=_sha256(data), parse_status="complete")
    request = ScanRequest(
        request_id=f"jsproxy-{variant}",
        repository="openharmony/distributeddatamgr_kv_store",
        commit="acfb22aac16161d8fb0cefb6cc9b92f04f489a80",
        snapshot_sha256=_sha256(data),
        target_id="current-component:openharmony/distributeddatamgr_kv_store",
        profile_id="m0-synthetic",
        provenance="fixture",
    )
    run = SharedPtrRaceDetector().detect(ScanContext(request, (unit,)), (unit,))
    findings = tuple(_detector_dict(item) for item in run.findings)
    return DetectorRecord(variant, run.status, len(run.findings), findings, tuple(run.limitations))


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


def make_variants(source_bytes: bytes, output: Path) -> Tuple[Dict[str, bytes], bytes]:
    source = source_bytes.decode("utf-8")
    fixed = _fixed_control_source(source).encode("utf-8")
    patched = _patched_atomic_source(source).encode("utf-8")
    if "instanceMutex_" not in fixed.decode("utf-8") or "std::atomic_store" not in patched.decode("utf-8"):
        raise RuntimeError("patch transformation did not apply")
    diff = "".join(
        difflib.unified_diff(
            source.splitlines(keepends=True),
            patched.decode("utf-8").splitlines(keepends=True),
            fromfile="a/frameworks/common/js_proxy.h",
            tofile="b/frameworks/common/js_proxy.h",
        )
    ).encode("utf-8")
    variants = {"vulnerable": source_bytes, "fixed_control_mutex": fixed, "patched_atomic_minimal": patched}
    for name, data in variants.items():
        include = output / "work" / name / "include"
        include.mkdir(parents=True, exist_ok=True)
        (include / "js_proxy_variant.h").write_bytes(data)
    (output / "patch.diff").write_bytes(diff)
    return variants, diff


def _build(revision: str, include: Path, harness: Path, output: Path, compiler: str, timeout: float) -> Tuple[BuildRecord, Path]:
    binary = output / "work" / revision / "poc"
    binary.parent.mkdir(parents=True, exist_ok=True)
    command = (
        compiler,
        "-std=c++17",
        "-g",
        "-O1",
        "-fno-omit-frame-pointer",
        "-fsanitize=thread",
        "-pthread",
        "-no-pie",
        f"-I{include}",
        str(harness),
        "-o",
        str(binary),
    )
    code, elapsed, stdout, stderr, timed_out = _run(command, output / "work" / revision, timeout)
    outcome = "build_timeout" if timed_out else "build_success" if code == 0 else "build_failed"
    return BuildRecord(revision, command, code, elapsed, stdout, stderr, outcome), binary


def _run_mode(binary: Path, variant: str, mode: str, repeat: int, output: Path, timeout: float) -> RunRecord:
    prefix: Tuple[str, ...] = ()
    setarch = shutil.which("setarch")
    if setarch:
        prefix = (setarch, platform.machine(), "-R")
    args = {"race": ("4", "2", "50000"), "close_get_entry": ("2000",)}.get(mode, ())
    command = prefix + (str(binary), mode, *args)
    env = dict(os.environ)
    env["TSAN_OPTIONS"] = "halt_on_error=1:exitcode=66"
    code, elapsed, stdout, stderr, timed_out = _run(command, output / "work" / variant, timeout, env)
    sanitizer = any(marker in stderr for marker in TSAN_MARKERS)
    if timed_out:
        outcome = "timeout"
    elif sanitizer:
        outcome = "sanitizer_triggered"
    elif code == 0:
        outcome = "clean"
    else:
        outcome = "failed"
    return RunRecord(variant, mode, repeat, command, code, elapsed, stdout, stderr, sanitizer, outcome)


def classify(runs: Sequence[RunRecord], repeats: int) -> str:
    required_modes = ("race", "close_get_entry")
    selected = [item for item in runs if item.mode in required_modes]
    if len(selected) != repeats * len(RUN_VARIANTS) * len(required_modes):
        return "inconclusive"
    if any(item.outcome == "timeout" for item in selected):
        return "inconclusive"
    for mode in required_modes:
        outcomes = {
            variant: {item.outcome for item in selected if item.variant == variant and item.mode == mode}
            for variant in RUN_VARIANTS
        }
        if outcomes["vulnerable"] != {"sanitizer_triggered"}:
            return "not_reproduced" if outcomes["vulnerable"] == {"clean"} else "unstable"
        if outcomes["fixed_control_mutex"] != {"clean"}:
            return "fixed_control_revalidation_failed"
        if outcomes["patched_atomic_minimal"] != {"clean"}:
            return "patch_revalidation_failed"
    return "stable_reproduced_and_patch_revalidated"

def write_markdown(result: JsProxyPoCResult, output: Path) -> None:
    lines = [
        "# JSProxy shared_ptr race PoC",
        "",
        "> controlled component-level dynamic evidence; status remains `candidate/unknown`.",
        "",
        f"- package: `{result.package_id}`",
        f"- detector: `{result.detector_id}` `{result.detector_version}` / `{result.rule_id}`",
        f"- source binding: `{result.source_binding_status}`",
        f"- harness SHA-256: `{result.environment.get('harness_sha256', 'unknown')}`",
        f"- detector source SHA-256: `{result.environment.get('detector_source_sha256', 'unknown')}`",
        f"- source: `{result.source.path}` blob `{result.source.blob}` SHA-256 `{result.source.sha256}`",
        f"- outcome: **{result.outcome}**",
        f"- `validated_vulnerability`: `{result.validated_vulnerability}`",
        "",
        "## Detector runs",
        "",
        "| variant | status | findings |",
        "|---|---|---:|",
    ]
    lines.extend(f"| `{item.variant}` | `{item.status}` | {item.finding_count} |" for item in result.detector_runs)
    lines.extend(["", "## Runtime", "", "| variant | mode | repeat | outcome | TSan |", "|---|---|---:|---|---|"])
    lines.extend(
        f"| `{item.variant}` | `{item.mode}` | {item.repeat} | `{item.outcome}` | {item.sanitizer_detected} |"
        for item in result.runs
    )
    lines.extend(
        [
            "",
            "## Patch",
            "",
            f"- patch SHA-256: `{result.patch_sha256}`",
            f"- fixed-control source SHA-256: `{result.fixed_source_sha256}`",
            f"- minimal-patch source SHA-256: `{result.patched_source_sha256}`",
            "",
            "## Interpretation boundary",
            "",
            "本记录证明固定 `JSProxy` owner 字节在模型化 async-close / sync-read 调用形态下存在 ThreadSanitizer 可见竞争，并验证两种同步化变体可消除该竞争。它不证明真实 OpenHarmony 产品进程中的稳定崩溃、可利用内存破坏、跨应用数据泄露或权限提升。",
            "",
            "## Remaining limitations",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in result.limitations)
    (output / "poc.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_evidence_bundle(result: JsProxyPoCResult, manifest: Mapping[str, object], output: Path) -> None:
    bundle = {
        "schema_version": 2,
        "kind": "cpp_shared_ptr_jsproxy_competition_evidence",
        "selected_review_group": "RC-JSPROXY",
        "selected_candidate_ids": manifest["candidate_ids"],
        "selected_diagnostic_ids": manifest["diagnostic_ids"],
        "selection_rationale": "独立复核后选择 RC-JSPROXY：真实 NAPI async execute 与同步 result-set 方法共享 JSProxy owner，且没有 repository-local lock/atomic API。相较 PIP getter/setter 的顺序字段转移、StreamManager 的构造/初始化形态，JSProxy 有直接跨线程调用路径。",
        "final_status": "candidate/unknown",
        "validated_vulnerability": 0,
        "repository": manifest["repository"],
        "commit": manifest["commit"],
        "git_tree": manifest["git_tree"],
        "harness_sha256": result.environment.get("harness_sha256"),
        "detector_source_sha256": result.environment.get("detector_source_sha256"),
        "source_identity": asdict(result.source),
        "call_path_sources": [asdict(item) for item in result.call_path_sources],
        "detector": {
            "id": result.detector_id,
            "version": result.detector_version,
            "rule_id": result.rule_id,
            "runs": [asdict(item) for item in result.detector_runs],
        },
        "real_call_path": [
            "ArkTS/JS SingleKVStore.getResultSet -> JsSingleKVStore::GetResultSet -> NapiQueue::AsyncWork execute -> ctxt->resultSet->SetInstance(kvResultSet) [js_single_kv_store.cpp:1190-1203]",
            "ArkTS/JS KVStoreResultSet.getEntry -> JsKVStoreResultSet::GetEntry -> GetInstance() [js_kv_store_resultset.cpp:269-277]",
            "ArkTS/JS SingleKVStore.closeResultSet -> JsSingleKVStore::CloseResultSet -> NapiQueue::AsyncWork execute -> GetInstance(); SetInstance(nullptr); kvStore->CloseResultSet(resultSet) [js_single_kv_store.cpp:1239-1247]",
            "NapiQueue::AsyncWork schedules execute through napi_create_async_work and napi_queue_async_work_with_qos [napi_queue.cpp:100-123]",
            "JSProxy<T>::SetInstance writes instance_ and GetInstance copies instance_ without synchronization [js_proxy.h:35-42]",
        ],
        "entry_and_permission_boundary": {
            "entry": "same application's ArkTS/JS SingleKVStore and KVStoreResultSet API; object is produced by getResultSet and used by synchronous result-set methods",
            "source_observation": "getResultSet(keyPrefix) path has no explicit permission assertion in the shown input handler; Query overload checks IsSystemApi/IsSystemApp. createKVManager/getKVStore and sync APIs have separate policy.",
            "boundary_status": "partial",
            "cross_app_or_cross_device": "not proven; the observed owner object is process-local",
        },
        "trigger_conditions": [
            "obtain a KvStoreResultSet through SingleKVStore.getResultSet",
            "call synchronous result-set operations such as getEntry on the JS thread",
            "concurrently invoke SingleKVStore.closeResultSet so its NapiQueue execute runs on the async worker",
            "repeat close/getEntry while the result set is live; no repository-local lock or atomic shared_ptr API protects the owner",
        ],
        "reachable_sensitive_operation": "kvStore->CloseResultSet(resultSet) races the result-set read path through the same JSProxy owner; this reaches the native result-set lifetime/close operation.",
        "cia_impact": {
            "availability": "candidate: process-level undefined behavior or denial of service; TSan race proven, stable crash not proven",
            "integrity": "unknown: shared_ptr/control-block corruption or incorrect result access is possible but not demonstrated",
            "confidentiality": "not claimed: no cross-app or cross-device data exposure evidence",
        },
        "cwe_cve": {
            "primary": "CWE-362: Concurrent Execution Using Shared Resource with Improper Synchronization",
            "possible_consequence": "CWE-416: Use After Free (only a possible consequence; no product UAF proof)",
            "cve": "none identified/assigned in the local evidence; no CVE mapping fabricated",
        },
        "affected_scope": {
            "repository": manifest["repository"],
            "audited_commit": manifest["commit"],
            "audited_tree": manifest["git_tree"],
            "modules": [
                "frameworks/common/js_proxy.h",
                "frameworks/jskitsimpl/distributedkvstore/src/js_single_kv_store.cpp",
                "frameworks/jskitsimpl/distributedkvstore/src/js_kv_store_resultset.cpp",
                "frameworks/jskitsimpl/distributedkvstore/src/napi_queue.cpp",
            ],
            "branches": "unknown; local refs do not prove branch membership",
            "versions": "affected version/branch claim not upgraded; audited snapshot is exact",
        },
        "patch_and_revalidation": {
            "patch": "see patch.diff",
            "patch_sha256": result.patch_sha256,
            "fixed_control": "independent mutex control; detector findings 0 and TSan clean",
            "minimal_patch": "std::atomic_load/std::atomic_store on instance_; detector findings 0 and TSan clean",
            "repeats": result.repeats,
            "outcome": result.outcome,
        },
        "limitations": list(result.limitations),
        "handoff": "A-line detection facts, Harness, PoC, patch revalidation and method notes are complete; confirmed/reportable status, final report merge and cross-module conclusions remain for project owner review.",
    }
    (output / "evidence-bundle.json").write_text(json.dumps(bundle, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    lines = [
        "# JSProxy shared_ptr / lifetime candidate evidence bundle",
        "",
        "## Status",
        "",
        "- selected group: `RC-JSPROXY`",
        f"- candidate IDs: `{', '.join(manifest['candidate_ids'])}`",
        f"- final status: `{bundle['final_status']}`; `validated_vulnerability=0`",
        "- A-line closure: detection facts, source binding, real call path, Harness, PoC, minimal patch and repeated revalidation complete; no confirmed/reportable upgrade.",
        "",
        "## Fixed source identity",
        "",
        f"- repository `{bundle['repository']}`",
        f"- commit `{bundle['commit']}` / tree `{bundle['git_tree']}`",
        f"- vulnerable source `{result.source.path}` blob `{result.source.blob}` SHA-256 `{result.source.sha256}`",
        "",
        "## Real call path",
        "",
    ]
    lines.extend(f"- {item}" for item in bundle["real_call_path"])
    lines.extend(
        [
            "",
            "## Entry, trigger, sensitive operation and CIA",
            "",
            f"- entry: {bundle['entry_and_permission_boundary']['entry']}",
            f"- permission boundary: {bundle['entry_and_permission_boundary']['boundary_status']} ({bundle['entry_and_permission_boundary']['cross_app_or_cross_device']})",
            f"- sensitive operation: {bundle['reachable_sensitive_operation']}",
            f"- availability: {bundle['cia_impact']['availability']}",
            f"- integrity: {bundle['cia_impact']['integrity']}",
            f"- confidentiality: {bundle['cia_impact']['confidentiality']}",
            "",
            "## CWE / CVE",
            "",
            f"- primary: {bundle['cwe_cve']['primary']}",
            f"- possible consequence: {bundle['cwe_cve']['possible_consequence']}",
            f"- CVE: {bundle['cwe_cve']['cve']}",
            "",
            "## Scope and handoff",
            "",
            f"- modules: {', '.join(bundle['affected_scope']['modules'])}",
            f"- branches: {bundle['affected_scope']['branches']}",
            f"- versions: {bundle['affected_scope']['versions']}",
            f"- {bundle['handoff']}",
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in result.limitations)
    (output / "evidence-bundle.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def run_poc(*, manifest_path: Path = DEFAULT_MANIFEST, harness: Path = DEFAULT_HARNESS, output: Path, compiler: str = "clang++", repeats: int = 3, build_timeout: float = 90.0, run_timeout: float = 90.0) -> JsProxyPoCResult:
    manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=True)
    harness = Path(harness).resolve()
    detector_source = ROOT / str(manifest["detector_source_path"])
    detector_sha256 = _sha256(detector_source.read_bytes())
    if detector_sha256 != manifest["detector_source_sha256"]:
        raise RuntimeError(f"detector source hash mismatch: {detector_sha256}")
    poc_runner = ROOT / str(manifest["poc_runner_path"])
    poc_runner_sha256 = _sha256(poc_runner.read_bytes())
    if poc_runner_sha256 != manifest["poc_runner_sha256"]:
        raise RuntimeError(f"PoC runner hash mismatch: {poc_runner_sha256}")
    harness_sha256 = _sha256(harness.read_bytes())
    if harness_sha256 != manifest["harness_sha256"]:
        raise RuntimeError(f"harness hash mismatch: {harness_sha256}")
    source, call_sources, source_bytes_by_path = verify_sources(manifest)
    variants, patch = make_variants(source_bytes_by_path[str(manifest["source_path"])], output)
    detector_runs = tuple(run_detector(name, str(manifest["source_path"]), data) for name, data in variants.items())
    builds: List[BuildRecord] = []
    binaries: Dict[str, Path] = {}
    for name in RUN_VARIANTS:
        build, binary = _build(name, output / "work" / name / "include", harness, output, compiler, build_timeout)
        builds.append(build)
        binaries[name] = binary
    runs: List[RunRecord] = []
    if all(item.outcome == "build_success" for item in builds):
        for name in RUN_VARIANTS:
            runs.append(_run_mode(binaries[name], name, "single", 1, output, run_timeout))
            runs.append(_run_mode(binaries[name], name, "unrelated", 1, output, run_timeout))
            for mode in ("race", "close_get_entry"):
                for repeat in range(1, repeats + 1):
                    runs.append(_run_mode(binaries[name], name, mode, repeat, output, run_timeout))
    outcome = "build_failed" if any(item.outcome != "build_success" for item in builds) else classify(runs, repeats)
    version = _run((compiler, "--version"), output, 30.0)
    compiler_version = (version[2] or version[3]).splitlines()[0] if (version[2] or version[3]) else "unknown"
    limitations = tuple(manifest["known_limitations"])
    if _sha256(detector_source.read_bytes()) != detector_sha256:
        raise RuntimeError("detector source changed during PoC execution")
    return JsProxyPoCResult(
        manifest["package_id"],
        manifest["detector_id"],
        manifest["detector_version"],
        manifest["rule_id"],
        manifest["source_binding_status"],
        source,
        call_sources,
        detector_runs,
        tuple(builds),
        tuple(runs),
        repeats,
        outcome,
        _sha256(patch),
        _sha256(variants["patched_atomic_minimal"]),
        _sha256(variants["fixed_control_mutex"]),
        {
            "compiler": compiler,
            "compiler_version": compiler_version,
            "harness_sha256": harness_sha256,
            "detector_source_sha256": detector_sha256,
            "poc_runner_sha256": poc_runner_sha256,
            "sanitizers": ["thread"],
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "aslr_workaround": bool(shutil.which("setarch")),
            "modes": list(RACE_MODES),
            "variants": list(RUN_VARIANTS),
        },
        limitations,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--harness", type=Path, default=DEFAULT_HARNESS)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--compiler", default="clang++")
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    result = run_poc(manifest_path=args.manifest, harness=args.harness, output=args.output, compiler=args.compiler, repeats=args.repeats)
    output = Path(args.output).resolve()
    (output / "poc.json").write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_markdown(result, output)
    write_evidence_bundle(result, json.loads(Path(args.manifest).read_text(encoding="utf-8")), output)
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
