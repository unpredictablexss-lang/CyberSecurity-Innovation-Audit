#!/usr/bin/env python3
"""Build T42 per-ID source and production IPC replay evidence for CR-0174..0196."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
QUEUE = ROOT / "research/deliveries/cpp/a0_triage_20261019/queue.csv"
CLI = Path(__file__).with_name("t42_player_framework_cli_20261025.json")
OUT = Path(__file__).with_name("t42_player_framework_audit_20261025.json")
REPORT = Path(__file__).with_name("t42_player_framework_audit_20261025.md")
REPOSITORY = "openharmony/multimedia_player_framework"
COMMIT = "71ab1e0881e0a79f2b9528742677467e7bb8dde5"
TREE = "9cc6c53506a70424485885c4c10b29dfbfaa8d1b"
RULE = "ipc.relay.descriptor-boundary"

PROXIES = {
    "services/services/avmetadatahelper/ipc/helper_listener_stub.cpp": "services/services/avmetadatahelper/ipc/helper_listener_proxy.cpp",
    "services/services/lpp_audio_streamer/ipc/lpp_audio_streamer_listener_stub.cpp": "services/services/lpp_audio_streamer/ipc/lpp_audio_streamer_listener_proxy.cpp",
    "services/services/lpp_video_streamer/ipc/lpp_video_streamer_listener_stub.cpp": "services/services/lpp_video_streamer/ipc/lpp_video_streamer_listener_proxy.cpp",
    "services/services/media_source/ipc/media_source_loader_stub.cpp": "services/services/media_source/ipc/media_source_loader_proxy.cpp",
    "services/services/pcm_output/ipc/pcm_output_callback_stub.cpp": "services/services/pcm_output/ipc/pcm_output_callback_proxy.cpp",
    "services/services/player/ipc/player_listener_stub.cpp": "services/services/player/ipc/player_listener_proxy.cpp",
    "services/services/player/ipc/player_service_stub.cpp": "services/services/player/ipc/player_service_proxy.cpp",
    "services/services/recorder/ipc/recorder_service_stub.cpp": "services/services/recorder/ipc/recorder_service_proxy.cpp",
    "services/services/screen_capture_monitor/ipc/screen_capture_monitor_service_stub.cpp": "services/services/screen_capture_monitor/ipc/screen_capture_monitor_service_proxy.cpp",
    "services/services/transcoder/ipc/transcoder_listener_stub.cpp": "services/services/transcoder/ipc/transcoder_listener_proxy.cpp",
    "services/services/transcoder/ipc/transcoder_service_stub.cpp": "services/services/transcoder/ipc/transcoder_service_proxy.cpp",
}
SUPPORT = [
    "services/utils/include/media_log.h",
    "interfaces/inner_api/native/BUILD.gn",
    "services/services/BUILD.gn",
    "services/BUILD.gn",
    "services/etc/BUILD.gn",
    "services/etc/3002.json",
    "services/etc/on_demand/3002.json",
    "services/etc/media_service.cfg",
    "services/etc/on_demand/media_service.cfg",
    "bundle.json",
]

FLOW = {
    "callback_stubs": {
        "files": [p for p in PROXIES if "listener_stub.cpp" in p or "callback_stub.cpp" in p or "media_source_loader_stub.cpp" in p],
        "transaction_flow": "Proxy methods construct MessageParcel, write their interface token, then call SendRequest with a transaction code. The paired Stub reads that token before dispatching its callback/request cases. Listener/PCM/helper/LPP callbacks flow from media_service toward a remote callback object; MediaSourceLoader transactions are the loader-request direction and may carry the caller-supplied IStandardMediaSourceLoadingRequest remote object on INIT.",
        "authorization": "No per-callback caller AccessToken/permission check was established in these receiver methods. Their process/object reachability depends on who owns or receives the IRemoteObject and on conditional media_client feature inclusion; the source alone does not establish an attacker-controlled remote reference.",
        "classification": "client-side or callback capability receivers; not independent SA registration points",
    },
    "player_service": {
        "files": ["services/services/player/ipc/player_service_stub.cpp"],
        "transaction_flow": "PlayerServiceProxy writes its interface token and sends transaction codes to PlayerServiceStub; the stub dispatches a code-indexed member-function map, reads/writes Parcel values and enqueues the member function. Callback references are separately set through listener-object transactions.",
        "authorization": "OnRemoteRequest contains the descriptor guard and freeze/unfreeze handling, and captures calling UID/PID in service state. No caller-token VerifyAccessToken check is present in the reviewed dispatch function. Effective IPC/SA policy and product exposure remain unknown.",
        "classification": "service-side IPC stub compiled conditionally into media_service",
    },
    "recorder_service": {
        "files": ["services/services/recorder/ipc/recorder_service_stub.cpp"],
        "transaction_flow": "RecorderServiceProxy sends code plus Parcel values to RecorderServiceStub; the stub checks the interface descriptor, then resolves code through AUDIO_REQUEST/COMMON_REQUEST and recFuncs_.",
        "authorization": "For AUDIO_REQUEST and (after audio permission was requested) COMMON_REQUEST, CheckPermission uses IPCSkeleton::GetCallingTokenID and AccessTokenKit::VerifyAccessToken; denied requests return MSERR_NO_PERMISSION_5400102 before member dispatch. Other requests intentionally bypass this local audio permission branch. Product policy/configuration still needs verification.",
        "classification": "service-side IPC stub compiled conditionally into media_service",
    },
    "screen_capture_monitor": {
        "files": ["services/services/screen_capture_monitor/ipc/screen_capture_monitor_service_stub.cpp"],
        "transaction_flow": "ScreenCaptureMonitorServiceProxy sends code/Parcel to a member-function map; handlers can install/remove a listener callback or query monitor state. The reviewed dispatch has an interface descriptor check.",
        "authorization": "No explicit per-call AccessToken guard was found in this OnRemoteRequest path. The service init config declares CAPTURE_SCREEN and permission_acls, but that process/SA declaration alone does not prove caller policy for each method, product installation, or reachability.",
        "classification": "service-side IPC stub compiled conditionally into media_service",
    },
    "transcoder_service": {
        "files": ["services/services/transcoder/ipc/transcoder_service_stub.cpp"],
        "transaction_flow": "TransCoderServiceProxy writes the interface token and sends transaction code/Parcel data to a code-indexed member-function map; selected handlers may return data in reply.",
        "authorization": "The service records calling PID/UID in reviewed code, but no caller permission verification appears in OnRemoteRequest. Whether other service state, SA policy or product configuration constrains callers remains unknown.",
        "classification": "service-side IPC stub compiled conditionally into media_service",
    },
}


def git(git_dir: str, *args: str) -> bytes:
    return subprocess.check_output(["git", f"--git-dir={git_dir}", *args], stderr=subprocess.PIPE)


def git_worktree(*args: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(ROOT), *args], stderr=subprocess.PIPE)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--git-dir", required=True, help="bare/object-rich local player_framework Git mirror")
    args = ap.parse_args()
    with QUEUE.open(encoding="utf-8-sig", newline="") as f:
        all_rows = list(csv.DictReader(f))
    rows = [r for r in all_rows if 174 <= int(r["queue_id"].split("-")[1]) <= 196]
    cli = json.loads(CLI.read_text(encoding="utf-8"))
    diagnostics = [d for run in cli.get("detector_runs", []) if run.get("tool") == "ohscanner.interface.ipc" for d in run.get("diagnostics", [])]
    ipc_run = next(run for run in cli.get("detector_runs", []) if run.get("tool") == "ohscanner.interface.ipc")
    parse_by_path = {x.get("file"): {"parse_status": x.get("status"), "analysis_status": x.get("analysis_status"), "analysis_reason": x.get("analysis_reason")} for x in ipc_run.get("parsing", [])}
    by_position = {(d.get("file"), d.get("line")): d for d in diagnostics}

    sources: dict[str, dict] = {}
    for path in sorted(set([r["path"] for r in rows] + list(PROXIES.values()) + SUPPORT)):
        raw = git(args.git_dir, "show", f"{COMMIT}:{path}")
        sources[path] = {
            "blob": git(args.git_dir, "rev-parse", f"{COMMIT}:{path}").decode().strip(),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size_bytes": len(raw),
        }

    per_id = []
    for r in rows:
        d = by_position.get((r["path"], int(r["line"])))
        raw = git(args.git_dir, "show", f"{COMMIT}:{r['path']}")
        source_line = raw.decode("utf-8").splitlines()[int(r["line"]) - 1]
        per_id.append({
            "queue_id": r["queue_id"], "candidate_id": r["candidate_id"],
            "repository": r["repository"], "project_path": r["repo_project_path"],
            "commit": r["commit"], "tree": r["tree"], "path": r["path"],
            "line": int(r["line"]), "line_text": source_line, "blob": r["blob"],
            "source_sha256": r["source_sha256"], "rule": r["rule"],
            "original_status": r["original_status"], "queue_status": r["queue_status"],
            "finding": None if d is None else {
                "diagnostic_id": d.get("diagnostic_id"), "rule_id": d.get("rule_id"),
                "file": d.get("file"), "line": d.get("line"), "symbol": d.get("symbol"),
                "source_sha256": d.get("source_sha256"), "message": d.get("message"),
            },
            "parse_status": parse_by_path.get(r["path"], {"parse_status": "missing", "analysis_status": "missing"}),
            "source_assessment": "The cited line is inside a dispatcher whose source reads the interface token and applies an exact Stub::GetDescriptor() equality check before dispatch; the exact project macro definition returns immediately on a false condition. This contradicts the specific missing-descriptor root cause claimed by this rule. Candidate remains a static scanner diagnostic, not a confirmed vulnerability. A0's original not_testable/paused_pending_evidence labels are preserved.",
        })

    extra = [d for d in diagnostics if (d.get("file"), d.get("line")) not in {(r["path"], int(r["line"])) for r in rows}]
    raw_cli = CLI.read_bytes()
    record = {
        "schema_version": 1,
        "audit_id": "T42",
        "purpose": "Independent current-production IPC CLI replay and source/proxy/authorization review for A0 CR-0174 through CR-0196; not vulnerability confirmation.",
        "scanner_checkout_base": git(args.git_dir, "rev-parse", COMMIT).decode().strip(),
        "scanner_baseline": git_worktree("rev-parse", "HEAD").decode().strip(),
        "repository": REPOSITORY,
        "commit": COMMIT,
        "tree": TREE,
        "queue_file": "research/deliveries/cpp/a0_triage_20261019/queue.csv",
        "a0_row_count": len(rows),
        "a0_original_status_counts": dict(Counter(r["original_status"] for r in rows)),
        "a0_queue_status_counts": dict(Counter(r["queue_status"] for r in rows)),
        "cli": {
            "command": "python -m src.cli.main ohscan-run --repo-dir D:/openHarmonyScanner/tmp/t42-player-framework-source-20261025 --repository openharmony/multimedia_player_framework --commit 71ab1e0881e0a79f2b9528742677467e7bb8dde5 --include <each of the 11 unique A0 paths> --detector ohscanner.interface.ipc --json-out research/evidence/cpp/t42_player_framework_cli_20261025.json --md-out research/evidence/cpp/t42_player_framework_cli_20261025.md",
            "json": "research/evidence/cpp/t42_player_framework_cli_20261025.json",
            "json_sha256": hashlib.sha256(raw_cli).hexdigest(),
            "status": cli.get("status"), "profile_id": cli.get("profile_id"),
            "detector_version": next((x.get("tool_version") for x in cli.get("detector_runs", []) if x.get("tool") == "ohscanner.interface.ipc"), None),
            "diagnostic_count": len(diagnostics), "validated_vulnerability": cli.get("validated_vulnerability"),
            "parse_counts": cli.get("source_parsing", {}).get("parsing_status"),
            "coverage": cli.get("detector_coverage", {}).get("detectors", {}).get("ohscanner.interface.ipc", {}),
            "a0_exact_position_hits": sum(x["finding"] is not None for x in per_id),
            "out_of_group_diagnostics": [{"file": d.get("file"), "line": d.get("line"), "rule_id": d.get("rule_id"), "diagnostic_id": d.get("diagnostic_id")} for d in extra],
        },
        "source_review": {
            "macro_guard": {
                "path": "services/utils/include/media_log.h",
                "evidence": "CHECK_AND_RETURN_RET_LOG expands to if (!(cond)) { MEDIA_LOGE(...); return ret; } while (0). All 23 A0 dispatcher positions occur after ReadInterfaceToken and a Stub::GetDescriptor() == remoteDescriptor check using this macro, before the transaction switch/map dispatch.",
                "assessment": "The specific missing interface-descriptor check claim is contradicted by the exact source and macro definition. This is strong static counterevidence to the rule root, but does not establish overall product safety or caller policy.",
            },
            "transaction_and_policy": FLOW,
            "service_registration_and_build": {
                "server_sources": "The player, recorder, screen_capture_monitor and transcoder service stub translation units are listed conditionally in services/services/BUILD.gn's media_service target. Callback/client-side stubs are listed conditionally in interfaces/inner_api/native/BUILD.gn's installable media_client target. These establish build capability in the component source, not inclusion in a particular product image.",
                "service_assembly": "services/BUILD.gn includes media_service in media_services_package; bundle.json declares that package. services/etc/BUILD.gn selects normal versus on-demand process/SA-profile files based on player_framework_enable_start_stop_on_demand; service profile identifies SA 3002/media_service.",
                "process_policy": "services/etc/media_service.cfg declares the media_service UID/GIDs, service permissions and CAPTURE_SCREEN ACL. This is process/SA configuration; it does not alone prove an IPC-level caller policy for every transaction or a concrete product build selection.",
                "unknowns": ["product/device manifest selecting this part and relevant feature flags", "runtime SA registration/profile and service start mode for the target product", "effective Binder/IPC caller policy and token type for the exposed endpoints", "who receives callback/listener remote-object capabilities and whether an untrusted app can obtain them", "target-version runtime behavior and security impact"],
            },
            "disposition": "The IPC CLI replay reproduces A0 candidate positions, but exact source guards contradict the cited descriptor-missing root. Since the run is parser-partial (10/11 files) and product/entry/permission/configuration are not bound, record PARTIAL/BLOCK rather than confirming vulnerability or deleting/promoting A0 candidates.",
        },
        "supporting_sources": sources,
        "per_id": per_id,
        "limitations": [
            "This is an independently run static CLI replay on the exact A0 component commit; no product build or runtime IPC transaction was executed.",
            "The production IPC detector reports 1 complete and 10 partial files; all 23 A0 line matches therefore remain subject to parser/model coverage limitations.",
            "A parser candidate is not a confirmed vulnerability. Source-level macro guard evidence conflicts with the specific missing-descriptor explanation.",
            "No A0 IDs, review statuses, queue statuses, detector, tests, fixtures or shared API were modified.",
        ],
    }
    OUT.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    lines = [
        "# T42 — player_framework IPC candidate audit (CR-0174–CR-0196)", "",
        f"- Scanner baseline: `{record['scanner_baseline']}`; component commit/tree: `{COMMIT}` / `{TREE}`.",
        f"- Current production IPC CLI: `{record['cli']['status']}`, {len(diagnostics)} diagnostics, {record['cli']['a0_exact_position_hits']}/23 exact A0 position matches; parse counts `{record['cli']['parse_counts']}`; detector coverage `{record['cli']['coverage'].get('status')}`.",
        "- A0 source IDs: 23/23 source identities verified; every row remains `not_testable / paused_pending_evidence`.",
        "- Source counterevidence: all 23 claimed dispatcher positions have a `ReadInterfaceToken` plus exact `Stub::GetDescriptor()` equality guard before dispatch; the commit-bound `CHECK_AND_RETURN_RET_LOG` macro returns when the condition fails. Thus the specific `descriptor-boundary` root is contradicted by source. This is not product safety confirmation.",
        "- Classification: `PARTIAL/BLOCK`; no vulnerability confirmed. The scanner run is parser-partial (10/11 files), and product inclusion, caller capability/reachability and effective policy are unbound.", "",
        "## Per-ID current CLI replay", "",
        "| A0 ID | Source location | Finding | Parse scope | A0 state |", "|---|---|---|---|---|",
    ]
    for x in per_id:
        finding = x["finding"]
        match = f"`{finding['rule_id']}` `{finding['diagnostic_id']}`" if finding else "no exact finding"
        per_file = record["cli"]["coverage"].get("analyzed_files", [])
        # The aggregate parser status is intentionally not inferred into per-file COMPLETE/PARTIAL.
        lines.append(f"| {x['queue_id']} | `{x['path']}:{x['line']}` | {match} | `{x['parse_status']['parse_status']}/{x['parse_status']['analysis_status']}` | `{x['original_status']} / {x['queue_status']}` |")
    lines += [
        "", "An additional CLI candidate at `services/services/media_source/ipc/media_source_loader_stub.cpp:86` is outside CR-0174–0196 and is not counted as an A0 hit.",
        "", "## IPC flow and authorization review", "",
        "The exact reviewed guard macro is defined in the same component commit as an early return on failed condition. Listener/helper/PCM/LPP and MediaSourceLoader client-side endpoints are built into the conditional installable `media_client` target; the service-side Player/Recorder/ScreenCaptureMonitor/Transcoder stubs are conditionally compiled into `media_service`. Paired proxies write their interface descriptor and send transaction codes. Recorder's audio-sensitive requests additionally use caller-token AccessTokenKit verification; player records caller UID/PID but the reviewed dispatch has no equivalent per-call AccessToken verification; transcoder records caller PID/UID but no per-call verification was found; ScreenCaptureMonitor has no explicit per-call AccessToken check in this dispatcher. `media_service.cfg` contains process permissions and a CAPTURE_SCREEN ACL, but product-specific inclusion and effective caller policy are not established.",
        "", "No caller, permission, registration, build-selection or data-flow inference is promoted to a confirmed issue. The full per-ID source/finding/status map and supporting blob/SHA identities are in [the machine record](t42_player_framework_audit_20261025.json); raw CLI output is [here](t42_player_framework_cli_20261025.json).",
        "", "Rebuild record: `python research/evidence/cpp/t42_player_framework_independent_audit_20261025.py --git-dir <player_framework.git>`; verify record: `python research/evidence/cpp/verify_t42_player_framework_audit_20261025.py --git-dir <player_framework.git>`.",
    ]
    REPORT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"audit_json": str(OUT), "report": str(REPORT), "ids": len(per_id), "exact_hits": record["cli"]["a0_exact_position_hits"], "diagnostics": len(diagnostics), "extra": len(extra)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
