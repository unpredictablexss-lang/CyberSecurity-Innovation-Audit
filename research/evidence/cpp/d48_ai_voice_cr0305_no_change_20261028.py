#!/usr/bin/env python3
"""Source-bound replay for A0 CR-0305; no detector or queue mutation."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector


COMMIT = "19188608475123695def986a399641bfa64a49f7"
TREE = "0ec80bfd6532b91f450d2f84517c461a4f7a18ae"
QUEUE_SNAPSHOT = "a2499e0c8f9ba4ec53e169f6c88d46cc10004f69d6b1b7339f80cf9b5891a4d5"
TARGET = "services/intell_voice_service/server/sa/intell_voice_service_stub.cpp"
TARGET_BLOB = "79a9acae7a4bb5a6dab18b40159f2aab52fcb544"
TARGET_SHA256 = "55dc2d68954cf94eb41014010fc6696236d9839fa8246aebd2faa8d033d30fc6"

SUPPORT = {
    "services/intell_voice_service/server/sa/intell_voice_service_stub.h": (
        "36add8d87590def310e42ef9b0f450075590fddc",
        "c5672ae9b51c98f1512bc16fe40490c5c7cc529e359531284389c9c2f980d816",
    ),
    "services/intell_voice_service/server/sa/intell_voice_service.cpp": (
        "9e6893bf0a64ba6e1f060b645702f99a2745f3ff",
        "5002aa457c97f6b9ee5e705bb0a17ec079e7ad3cc13dd1e2bf2c2b3845bb72fb",
    ),
    "services/intell_voice_service/server/sa/intell_voice_service.h": (
        "00cf6778acf353ba5af77bec6bd9680e6e84d570",
        "c903176fc49c927eb7746f071baa6acba535ee36e5d48e3e7aacacd1a47195bd",
    ),
    "services/intell_voice_service/inc/i_intell_voice_service.h": (
        "0614e495b013cc6b2293294755e9d9fa1ba8d872",
        "0cc554c09d940affb266ef02b0e0f26bacbe81fcd0e18fabf779fb92d10e3a3c",
    ),
    "services/intell_voice_engine/proxy/intell_voice_service_proxy.cpp": (
        "8f7c04c36ed61b1da174deab3bf1668546d0878c",
        "b59123c455d1e965270fe56e5d40ed35c345398bcaf1d1650f0e7bdcdedfb3df",
    ),
    "services/etc/intell_voice_service.cfg": (
        "32d8c6076617cc83a945bad158b7a677f5649788",
        "5c1d93da7083095b5d8fc3ef8528405356ac4b3d83165d403d15478d00e540df",
    ),
    "sa_profile/intell_voice_service.json": (
        "1df3d649c20cb82a0064e9ff0241e44f407abd0a",
        "a331d600aa43f193af9c2fb4540a5e20e3b92e88d1ec717318428b552053b799",
    ),
    "services/intell_voice_service/BUILD.gn": (
        "d57ec1fbd94443fc9c150e295902bc917d714148",
        "3405424d680441938e91abc2faf1eea97cef13e0d7858ce8acae40d28399ab16",
    ),
    "intell_voice_service.gni": (
        "3ef5591d6c44088a28c65bf459165c12c967462d",
        "06ed4a81c37f6aeef4a3c3fd6d47681fb8800358521bef3559390dc392396a53",
    ),
    "utils/intell_voice_util.cpp": (
        "391a22676bbd8c7388d553e644994e3b7d863763",
        "9f25399ef0e44a50226cd46e34040165943e6498d4b376dfa2b756609d03216b",
    ),
}


def git(repo: str, *args: str) -> bytes:
    return subprocess.check_output(["git", "--git-dir", repo, *args])


def source(repo: str, path: str, expected: tuple[str, str] | None = None) -> tuple[str, dict]:
    raw = git(repo, "show", f"{COMMIT}:{path}")
    blob = git(repo, "rev-parse", f"{COMMIT}:{path}").decode().strip()
    digest = hashlib.sha256(raw).hexdigest()
    if expected and (blob, digest) != expected:
        raise AssertionError(f"source identity mismatch: {path} ({blob}, {digest})")
    return raw.decode("utf-8"), {"blob": blob, "sha256": digest, "bytes": len(raw)}


def require(text: str, fragment: str, label: str) -> None:
    if fragment not in text:
        raise AssertionError(f"missing source evidence: {label}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-git-dir", required=True, help="bare local Git object directory for the pinned repository")
    parser.add_argument("--output", type=Path, help="optional path for machine-readable replay JSON")
    args = parser.parse_args()
    repo = str(Path(args.source_git_dir))

    actual_tree = git(repo, "rev-parse", f"{COMMIT}^{{tree}}").decode().strip()
    if actual_tree != TREE:
        raise AssertionError(f"tree mismatch: {actual_tree}")

    target, target_identity = source(repo, TARGET, (TARGET_BLOB, TARGET_SHA256))
    units = []
    evidence: dict[str, dict] = {TARGET: target_identity}
    sources: dict[str, str] = {TARGET: target}
    for path, identity in SUPPORT.items():
        text, observed = source(repo, path, identity)
        evidence[path] = observed
        sources[path] = text

    stub_h = sources["services/intell_voice_service/server/sa/intell_voice_service_stub.h"]
    service_cpp = sources["services/intell_voice_service/server/sa/intell_voice_service.cpp"]
    service_h = sources["services/intell_voice_service/server/sa/intell_voice_service.h"]
    util_cpp = sources["utils/intell_voice_util.cpp"]
    proxy_cpp = sources["services/intell_voice_engine/proxy/intell_voice_service_proxy.cpp"]
    cfg = sources["services/etc/intell_voice_service.cfg"]
    profile = sources["sa_profile/intell_voice_service.json"]
    build = sources["services/intell_voice_service/BUILD.gn"]
    gni = sources["intell_voice_service.gni"]
    stub_cpp = target

    require(stub_h, "class IntellVoiceServiceStub : public IRemoteStub<IIntellVoiceService>", "Stub interface base")
    require(stub_cpp, "if (data.ReadInterfaceToken() != IIntellVoiceService::GetDescriptor())", "interface-token check")
    require(stub_cpp, "return it->second(data, reply);", "transaction dispatch")
    require(stub_cpp, "ret = CreateIntellVoiceEngine(type, engine);", "engine factory call")
    require(stub_cpp, "if (ret != 0) {\n        INTELL_VOICE_LOG_ERROR", "nonzero factory result exits before export")
    require(stub_cpp, "reply.WriteRemoteObject(engine->AsObject());", "reported export sink")
    require(service_h, "class IntellVoiceService : public SystemAbility, public IntellVoiceServiceStub", "service implementation binding")
    require(service_cpp, "auto ret = IntellVoiceUtil::VerifySystemPermission(OHOS_PERMISSION_INTELL_VOICE);", "factory permission check")
    require(service_cpp, "if (ret != INTELLIGENT_VOICE_SUCCESS) {\n        INTELL_VOICE_LOG_WARN(\"verify permission denied\");\n        return ret;", "permission denial return")
    require(service_cpp, "inst = ServiceManagerType::GetInstance().HandleCreateEngine(type);", "engine creation after permission check")
    factory_start = service_cpp.index("IntellVoiceService::CreateIntellVoiceEngine(")
    factory_end = service_cpp.index("IntellVoiceService::ReleaseIntellVoiceEngine(", factory_start)
    factory_body = service_cpp[factory_start:factory_end]
    permission_pos = factory_body.index("VerifySystemPermission(OHOS_PERMISSION_INTELL_VOICE)")
    deny_pos = factory_body.index("return ret;", permission_pos)
    create_pos = factory_body.index("HandleCreateEngine(type)")
    if not permission_pos < deny_pos < create_pos:
        raise AssertionError("permission denial does not dominate the pinned engine creation call")
    death_start = service_cpp.index("IntellVoiceService::RegisterDeathRecipient(")
    death_end = service_cpp.index("IntellVoiceService::DeregisterDeathRecipient(", death_start)
    death_body = service_cpp[death_start:death_end]
    if not (death_body.index("VerifySystemPermission") < death_body.index("return false;")
            < death_body.index("RegisterProxyDeathRecipient")):
        raise AssertionError("callback registration is not ordered behind the pinned permission check")
    require(util_cpp, "IPCSkeleton::GetCallingTokenID()", "calling token source")
    require(util_cpp, "AccessTokenKit::VerifyAccessToken(clientTokenId, permissionName)", "permission decision on caller token")
    require(util_cpp, "if (!CheckIsSystemApp())", "system-app gate")
    require(proxy_cpp, "SendRequest(HDI_INTELL_VOICE_SERVICE_CREATE_ENGINE, data, reply, option)", "proxy invokes creation transaction")
    require(proxy_cpp, "reply.ReadRemoteObject()", "proxy receives exported object")
    require(cfg, '"uid" : "intell_voice"', "SA process UID configuration")
    require(cfg, '"permission" : [\n                "ohos.permission.MANAGE_INTELLIGENT_VOICE"', "SA process permission list")
    require(profile, '"name": 312', "system-ability profile identifier")
    require(build, '"server/sa/intell_voice_service_stub.cpp"', "production server source target")
    require(gni, "intelligent_voice_framework_engine_enable = true", "default engine build feature")

    index = parse_source(target, language="cpp")
    unit = SourceUnit(TARGET, "cpp", target, TARGET_SHA256, index.parse_status,
                      tuple(str(issue) for issue in index.parse_issues))
    ordered = (unit,)
    run_snapshot = snapshot_digest(ordered)
    request = ScanRequest(
        "D48-CR0305-replay", "openharmony/ai_intelligent_voice_framework", COMMIT,
        run_snapshot, "current-component:openharmony/ai_intelligent_voice_framework",
        "light-ast", "git_object",
    )
    context = ScanContext(request, ordered, {"ast": {TARGET: index.to_dict()}})
    run = IpcInterfaceDetector().detect(context, ordered)
    matches = [finding for finding in run.findings
               if finding.file == TARGET and finding.line == 70
               and finding.rule_id == "ipc.capability.export"]
    if not matches:
        raise AssertionError("current production detector did not reproduce the CR-0305 root candidate")

    result = {
        "schema_version": 1,
        "task": "D48",
        "review_id": "CR-0305",
        "queue_id": "T2-0305",
        "original_a0_status": "not_testable",
        "a0_status_mutated": False,
        "source": {
            "repository": "openharmony/ai_intelligent_voice_framework",
            "commit": COMMIT,
            "tree": TREE,
            "a0_snapshot_sha256": QUEUE_SNAPSHOT,
            "target_file": TARGET,
            "target": target_identity,
            "supporting_files": {path: identity for path, identity in evidence.items() if path != TARGET},
            "scope_note": "The detector replay supplies the exact target file only; the A0 snapshot identity is recorded separately and is not the one-file run snapshot.",
        },
        "scanner": {
            "baseline_checkout": "f42fb91af26d6843c4559936199f167ac8ae6443",
            "detector_id": IpcInterfaceDetector.detector_id,
            "detector_version": IpcInterfaceDetector.version,
            "model_version": IpcInterfaceDetector.model_version,
            "run_scope": [TARGET],
            "run_snapshot_sha256": run_snapshot,
            "parse_status": unit.parse_status,
            "parse_issues": list(index.parse_issues),
            "run_status": run.status,
            "analysis_coverage": "target_translation_unit_complete; cross-file semantics are manually source-bound below, not included in detector scope",
            "findings": [{"file": f.file, "line": f.line, "rule_id": f.rule_id,
                          "message": f.message} for f in run.findings],
            "limitations": list(run.limitations),
        },
        "source_review": {
            "entry_dispatch": "OnRemoteRequest checks the interface token and dispatches the registered transaction; interface-token equality is not caller authorization.",
            "capability_export": "CreateEngineInner writes engine->AsObject() only if the virtual factory returns zero and engine is non-null; nonzero returns before export.",
            "permission_guard": "Pinned IntellVoiceService override calls VerifySystemPermission(MANAGE_INTELLIGENT_VOICE) before HandleCreateEngine; permission failure returns nonzero. The helper checks system-app/native status and AccessTokenKit.VerifyAccessToken on IPCSkeleton.GetCallingTokenID().",
            "secondary_guard": "RegisterDeathRecipient is called before creation and independently verifies the same permission before registering the supplied callback object.",
            "client_flow": "The pinned proxy sends HDI_INTELL_VOICE_SERVICE_CREATE_ENGINE and reads the returned remote object, showing a designed client flow but not arbitrary-caller reachability.",
            "build_context": "Pinned BUILD.gn includes the Stub in the server source set and default GN argument sets intelligent_voice_framework_engine_enable=true; product configuration and built image were not verified.",
            "sa_configuration": "Pinned cfg runs the service as intell_voice and lists permissions for the SA process. This is not evidence of which callers are granted MANAGE_INTELLIGENT_VOICE.",
        },
        "assessment": {
            "finding_reproduced": True,
            "specific_detector_gap_proven": False,
            "classification": "no_change; authorization is an interprocedural/virtual-callee fact outside this one-file bounded model, while CAP-01 remains an appropriate candidate pending external policy and runtime proof",
            "result": "PARTIAL/BLOCK",
            "still_unknown": [
                "The concrete product GN profile/variant and whether this target is built into the reviewed product image.",
                "Which caller principals actually hold MANAGE_INTELLIGENT_VOICE in the affected image.",
                "Whether a non-system/unauthorized caller can reach this SA in the product configuration.",
                "What engine capability the authorized recipient can invoke and whether that creates CIA impact.",
                "A trusted fixed-source or product-level regression comparison.",
            ],
            "rule_change": False,
            "catalog_or_schema_change": False,
        },
    }
    encoded = json.dumps(result, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    print("PASS D48: exact A0 commit/tree/blob/SHA bindings verified")
    print(f"PASS D48: {IpcInterfaceDetector.version} / {IpcInterfaceDetector.model_version}, {unit.parse_status} parse, CR-0305 root candidate reproduced at line 70")
    print("PASS D48: cross-file permission guard and configured client flow source-bound; product authorization remains unknown")
    print("PASS D48: no A0 status mutation; classification remains PARTIAL/BLOCK")
    if args.output:
        print(f"WROTE {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
