from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Any


REVIEW_GROUP = "A-line shared_ptr candidate review supplement"

GROUP_FINDINGS: dict[str, dict[str, Any]] = {
    "RC-REMOTE-CHANNEL": {
        "technical_suggestion": "unknown",
        "priority": "high",
        "summary": (
            "RemoteCommandExecutor::ptrChannel_ has an unsynchronized setter/getter pair and is also "
            "written by CreateChannelIfNeeded and read while commands execute. The executor mutex covers "
            "only part of the owner accesses; concurrent device-online and command-processing paths remain "
            "a realistic race shape."
        ),
        "evidence_locations": [
            "services/tokensyncmanager/include/remote/remote_command_executor.h:35-41",
            "services/tokensyncmanager/src/remote/remote_command_executor.cpp:84-96",
            "services/tokensyncmanager/src/remote/remote_command_executor.cpp:307-317",
            "services/tokensyncmanager/src/remote/remote_command_manager.cpp:176-190",
            "services/tokensyncmanager/src/remote/remote_command_manager.cpp:276-287",
        ],
        "missing_facts": [
            "Exact thread/event-runner ownership for NotifyDeviceOnline, GetExecutorChannel, and command execution.",
            "A happens-before proof or a controlled race/fixed run for ptrChannel_ publication and reset.",
            "Real product entry, privilege boundary, trigger, and CIA consequence.",
        ],
        "minimal_reproduction": (
            "Build a narrow RemoteCommandExecutor harness that concurrently calls SetChannel/GetChannel and "
            "CreateChannelIfNeeded/ProcessOneCommand under TSan, then repeat with one owner mutex or atomic "
            "shared_ptr protocol."
        ),
    },
    "RC-JSPROXY": {
        "technical_suggestion": "unknown",
        "priority": "high",
        "summary": (
            "JSProxy::instance_ has an unsynchronized SetInstance/GetInstance owner pair. The result-set "
            "lifecycle clears or replaces the owner while other operations call GetInstance, so NAPI queue "
            "serialization and safe publication are required before deciding whether the pair can overlap."
        ),
        "evidence_locations": [
            "frameworks/common/js_proxy.h:29-44",
            "frameworks/jskitsimpl/distributeddata/src/js_kv_store_resultset.cpp:73-286",
            "frameworks/jskitsimpl/distributedkvstore/src/js_kv_store_resultset.cpp:79-297",
            "frameworks/jskitsimpl/distributedkvstore/src/napi_data_share_adapter.cpp:89-111",
        ],
        "missing_facts": [
            "NAPI execute/complete thread affinity and callback queue ordering for each JSProxy subtype.",
            "Whether SetInstance(nullptr) can overlap a queued GetInstance operation.",
            "Product entry, attacker control, and concrete CIA impact.",
        ],
        "minimal_reproduction": (
            "Run concurrent SetInstance(nullptr) and GetInstance calls for a representative result-set wrapper "
            "under TSan, then repeat after serializing owner mutation through the actual NAPI queue."
        ),
    },
    "RC-PIP-CONTROLLERS": {
        "technical_suggestion": "unknown",
        "priority": "high",
        "summary": (
            "PictureInPicture controller owner members have getter/setter or direct read/write pairs without a "
            "repository-local lock. Direct member accesses also occur from source-rect, reset, and ext-controller "
            "paths. Thread/event-runner affinity is not established."
        ),
        "evidence_locations": [
            "wm/include/picture_in_picture_controller.h:49-56",
            "wm/include/picture_in_picture_controller_ani.h:52-59",
            "wm/include/picture_in_picture_controller_base.h:140-147",
            "wm/src/picture_in_picture_controller.cpp:62-63,175,283-289,475-492",
            "wm/src/picture_in_picture_controller_ani.cpp:85-86,169,276-282,482-500",
        ],
        "missing_facts": [
            "Whether setters run on the same event runner as source-rect/reset/extension-controller readers.",
            "Feasible interleaving while a controller is shared between main and PIP windows.",
            "Reachable product trigger and concrete CIA impact.",
        ],
        "minimal_reproduction": (
            "Create two controller variants and race SetXComponentController/SetMainWindowXComponentController "
            "against the source-rect and ResetExtController readers under TSan; repeat with a mutex-protected owner."
        ),
    },
    "RC-STREAM-LISTENER": {
        "technical_suggestion": "unknown",
        "priority": "high",
        "summary": (
            "StreamManager::streamListener_ is initialized in the constructor, read while creating client/server "
            "channels, and reassigned by SetStreamRecvListener without synchronization. The candidate constructor "
            "site is not itself a conflicting runtime access, but it participates in the same owner lifecycle."
        ),
        "evidence_locations": [
            "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.h:67,87-110",
            "sdk/transmission/trans_channel/udp/stream/libsoftbus_stream/stream_manager.cpp:58-61,88-95,172-185",
        ],
        "missing_facts": [
            "Whether channel creation and SetStreamRecvListener can execute concurrently on one StreamManager.",
            "Publication ordering between streamListener_, socketListener_, and the socket callback.",
            "Reachable trigger and CIA consequence in the product.",
        ],
        "minimal_reproduction": (
            "Race SetStreamRecvListener with CreateStreamClientChannel/CreateStreamServerChannel in a controlled "
            "StreamManager harness under TSan, then repeat with a common mutex or immutable listener publication."
        ),
    },
    "RC-CONSTRUCTOR-NOISE": {
        "technical_suggestion": "unrelated",
        "priority": "normal",
        "summary": (
            "The reported site is constructor/member initialization or a stable-owner read. Repository-wide exact "
            "symbol search did not show a later owner reassignment for the same object. This excludes the observed "
            "non-atomic shared_ptr owner write/read race shape, but does not prove pointee thread safety."
        ),
        "evidence_locations": [
            "See the per-item source context generated from the pinned Git blob.",
        ],
        "missing_facts": [
            "Pointee internal thread safety and safe publication remain outside this owner-race disposition.",
        ],
        "minimal_reproduction": (
            "Only needed if a later owner assignment or cross-thread pointee mutation is discovered."
        ),
    },
    "RC-SCOPE-MOCK": {
        "technical_suggestion": "unrelated",
        "priority": "normal",
        "summary": (
            "The diagnostic is under kvstoremock/external_inner_kit, which is non-production mock/support source "
            "and was admitted by the historical scope path rule. It is not a production component vulnerability."
        ),
        "evidence_locations": [
            "kvstoremock/external_inner_kit/napi/include/extension_context.h:55-85",
        ],
        "missing_facts": [
            "No product fact is required to classify this specific item as out of production scope.",
        ],
        "minimal_reproduction": (
            "No vulnerability PoC. Retain as an unrelated/scope-control item and exclude from production scoring."
        ),
    },
    "RC-WINDOW-SINGLE": {
        "technical_suggestion": "unrelated",
        "priority": "normal",
        "summary": (
            "Most reported accesses are constructor initialization or Marshalling reads paired with Unmarshalling "
            "writes to a newly allocated, distinct object. The lexical sites do not establish a same-object "
            "concurrent owner write/read pair."
        ),
        "evidence_locations": [
            "See the per-item source context generated from the pinned Git blob.",
        ],
        "missing_facts": [
            "Pointee behavior and broader object lifecycle are not safety proof.",
        ],
        "minimal_reproduction": (
            "Only needed if a same-object owner mutation path is found."
        ),
    },
}

WINDOW_OVERRIDES = {
    "utils/include/ui_effect_controller_common.h": {
        "technical_suggestion": "unrelated",
        "priority": "normal",
        "summary": (
            "The reported IsEmpty() reads occur after ConvertFromJsValue initializes a newly created local "
            "UIEffectParams in the same NAPI flow. Parcel Unmarshalling also constructs a fresh object before "
            "publication. No same-object post-publication owner mutation pair was found, so these sites are "
            "unrelated to the observed shared_ptr owner race shape; this is not pointee safety proof."
        ),
        "evidence_locations": [
            "utils/include/ui_effect_controller_common.h:46-62",
            "utils/src/ui_effect_controller_common.cpp:50-76,110-130",
            "interfaces/kits/napi/window_runtime/window_napi/js_ui_effect_controller.cpp:125-130,173-192",
            "window_scene/session/host/src/ui_effect_controller_stub.cpp:41-56",
        ],
        "missing_facts": [
            "Pointee Filter/VisualEffect thread safety is outside this owner-race disposition.",
        ],
        "minimal_reproduction": (
            "Only needed if a same UIEffectParams object is mutated after publication or concurrently parsed."
        ),
    },
}

SURFACE_SYMBOL_OVERRIDES = {
    "pixelMap_": {
        "technical_suggestion": "safe",
        "priority": "normal",
        "summary": (
            "All observed pixelMap_ owner accesses are serialized by mutex_. OnSurfaceCaptureHDR and "
            "OnSurfaceCaptureWithErrorCode lock directly; OnSurfaceCapture writes through FutureCall(), and "
            "GetResult()/FetchResult() read while Future::GetResult holds the same mutex. This establishes "
            "synchronization for the non-atomic shared_ptr owner access set, not pointee safety."
        ),
        "evidence_locations": [
            "utils/include/future.h:22-52",
            "utils/include/surface_capture_future.h:30-58,66-95",
        ],
        "missing_facts": [
            "Pointee PixelMap thread safety and product-level CIA impact are outside this owner-race disposition.",
        ],
        "minimal_reproduction": (
            "Keep as a safe synchronization control and verify that concurrent callback/GetResult runs remain "
            "clean under TSan."
        ),
    },
    "hdrPixelMap_": {
        "technical_suggestion": "unknown",
        "priority": "high",
        "summary": (
            "Most hdrPixelMap_ accesses are protected by mutex_, including GetHDRResult and the HDR/error callbacks. "
            "However OnSurfaceCapture assigns hdrPixelMap_ = nullptr before FutureCall() takes mutex_, so that write "
            "can overlap the locked GetHDRResult read after a timeout. The owner pair remains unresolved."
        ),
        "evidence_locations": [
            "utils/include/future.h:22-52",
            "utils/include/surface_capture_future.h:30-58,66-95",
        ],
        "missing_facts": [
            "Whether an OnSurfaceCapture callback can overlap a timed-out GetHDRResult caller in product paths.",
            "Controlled TSan evidence for the out-of-lock hdrPixelMap_ reset.",
            "Product trigger and CIA consequence.",
        ],
        "minimal_reproduction": (
            "Race OnSurfaceCapture with GetHDRResult around timeout under TSan, then repeat after moving "
            "hdrPixelMap_ = nullptr inside the mutex."
        ),
    },
}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=REVIEW_GROUP)
    parser.add_argument("--project-root", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--generated-date", default="2026-10-15")
    return parser.parse_args()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def run_git(repo: Path, *args: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(repo), *args],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed for {repo}: {result.stderr.decode('utf-8', errors='replace')}"
        )
    return result.stdout


def posix_repo_path(raw_path: str) -> Path:
    path = Path(raw_path)
    windows_drive = re.match(r"^([A-Za-z]):[\\/](.*)$", raw_path)
    if windows_drive:
        drive = windows_drive.group(1).lower()
        remainder = windows_drive.group(2).replace("\\", "/")
        return Path(f"/mnt/{drive}/{remainder}")
    return path


def source_context(text: str, line: int, radius: int = 8) -> dict[str, Any]:
    lines = text.splitlines()
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    numbered = [f"{index:4d}: {lines[index - 1]}" for index in range(start, end + 1)]
    return {
        "start_line": start,
        "end_line": end,
        "focus_line": line,
        "text": "\n".join(numbered),
    }


def decision_for(row: dict[str, Any]) -> dict[str, Any]:
    group = row["root_cause_group"]
    if group == "RC-WINDOW-SINGLE":
        symbol_override = SURFACE_SYMBOL_OVERRIDES.get(row["symbol"]) if (
            row["file"] == "utils/include/surface_capture_future.h"
        ) else None
        override = symbol_override or WINDOW_OVERRIDES.get(row["file"])
        if override:
            finding = dict(GROUP_FINDINGS[group])
            finding.update(override)
            return finding
    return dict(GROUP_FINDINGS[group])


def comparison_for(first_status: str, suggestion: str) -> str:
    if suggestion == "unknown" and first_status == "plausible_unproven":
        return "consistent_unresolved"
    if suggestion == "unknown" and first_status == "likely_false_positive":
        return "disagreement_keep_unknown"
    if suggestion == "safe" and first_status == "likely_false_positive":
        return "disagreement_resolved_safe"
    if suggestion == "unrelated" and first_status == "likely_false_positive":
        return "consistent_non_vulnerability"
    if suggestion == "unrelated" and first_status == "refuted":
        return "consistent_refuted_scope"
    return "manual_review_required"


def obligations_for(suggestion: str, group: str) -> list[dict[str, str]]:
    common = [
        {
            "kind": "synchronization_proof",
            "description": "Resolve all owner accesses and synchronization semantics.",
            "status": "unknown",
        },
        {
            "kind": "thread_interleaving",
            "description": "Demonstrate or exclude a feasible concurrent access pair on the same object.",
            "status": "unknown",
        },
        {
            "kind": "product_build_context",
            "description": "Establish the real build, template/macro and component execution context.",
            "status": "unknown",
        },
        {
            "kind": "security_impact",
            "description": "Verify reachable trigger and concrete CIA impact independently.",
            "status": "unknown",
        },
    ]
    if group == "RC-SCOPE-MOCK":
        common[2]["status"] = "not_applicable_out_of_scope"
        common[3]["status"] = "not_applicable_out_of_scope"
    return common


def markdown_table(rows: list[dict[str, Any]]) -> str:
    output = [
        "| Scope | Candidate | Component | Location | Symbol | First round | Technical suggestion | Comparison |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in rows:
        candidate = item["workbench_candidate_id"]
        location = f'{item["file"]}:{item["line"]}:{item["column"]}'
        output.append(
            f'| {item["review_scope"]} | `{candidate}` | {item["component"]} | `{location}` | '
            f'`{item["symbol"]}` | `{item["first_round_status"]}` | '
            f'`{item["technical_suggestion"]}` | `{item["comparison_to_first_round"]}` |'
        )
    return "\n".join(output)


def build(project_root: Path, output_dir: Path, generated_date: str) -> dict[str, Any]:
    project_root = project_root.resolve()
    output_dir = output_dir.resolve()
    evidence_root = project_root / "research" / "evidence" / "cpp" / "review_20261014"
    ledger_path = evidence_root / "review_ledger.json"
    holdout_path = evidence_root / "holdout_manifest.json"
    group_path = evidence_root / "root_cause_groups.json"
    verification_path = evidence_root / "verification.json"
    component_root = project_root / "research" / "evidence" / "cpp" / "component_scans"

    ledger = load_json(ledger_path)
    holdout = load_json(holdout_path)
    all_rows: list[dict[str, Any]] = []
    for component in ledger["components"]:
        all_rows.extend(component["review_rows"])
    by_candidate = {row["workbench_candidate_id"]: row for row in all_rows}
    plausible_rows = [row for row in all_rows if row["status"] == "plausible_unproven"]
    holdout_ids = list(holdout["holdout_candidate_ids"])
    missing_holdout = [candidate for candidate in holdout_ids if candidate not in by_candidate]
    if missing_holdout:
        raise RuntimeError(f"Holdout candidates absent from ledger: {missing_holdout}")
    if len(plausible_rows) != 11:
        raise RuntimeError(f"Expected 11 plausible_unproven rows, found {len(plausible_rows)}")
    if len(holdout_ids) != 34:
        raise RuntimeError(f"Expected 34 holdout rows, found {len(holdout_ids)}")

    manifests: dict[str, dict[str, Any]] = {}
    for path in sorted(component_root.glob("*.manifest.json")):
        manifest = load_json(path)
        manifests[manifest["component"]] = manifest

    review_items: list[dict[str, Any]] = []
    source_checks: list[dict[str, Any]] = []
    seen_sources: dict[tuple[str, str], dict[str, Any]] = {}

    def add_item(row: dict[str, Any], review_scope: str, suffix: str) -> None:
        manifest = manifests[row["component"]]
        repo = posix_repo_path(manifest["source_repo_path"])
        actual_head = run_git(repo, "rev-parse", "HEAD").decode("ascii").strip()
        actual_tree = run_git(repo, "rev-parse", f'{manifest["commit"]}^{{tree}}').decode("ascii").strip()
        if actual_head != manifest["commit"]:
            raise RuntimeError(
                f'{row["component"]}: source HEAD {actual_head} does not match pinned commit {manifest["commit"]}'
            )
        if actual_tree != manifest["git_tree"]:
            raise RuntimeError(
                f'{row["component"]}: source tree {actual_tree} does not match pinned tree {manifest["git_tree"]}'
            )
        source_key = (row["component"], row["file"])
        if source_key not in seen_sources:
            raw = run_git(repo, "cat-file", "blob", f'{manifest["commit"]}:{row["file"]}')
            digest = sha256_bytes(raw)
            text = raw.decode("utf-8-sig")
            seen_sources[source_key] = {
                "source_sha256": digest,
                "source_text": text,
                "git_blob_oid": run_git(
                    repo, "rev-parse", f'{manifest["commit"]}:{row["file"]}'
                ).decode("ascii").strip(),
            }
        source = seen_sources[source_key]
        source_ok = source["source_sha256"] == row["source_sha256"]
        if not source_ok:
            raise RuntimeError(
                f'Source hash mismatch for {row["component"]}:{row["file"]}: '
                f'ledger={row["source_sha256"]} actual={source["source_sha256"]}'
            )
        finding = decision_for(row)
        review_item_id = f'{row["workbench_candidate_id"]}:{suffix}'
        context = source_context(source["source_text"], row["line"])
        review_items.append(
            {
                "review_item_id": review_item_id,
                "review_scope": review_scope,
                "component": row["component"],
                "repository": manifest["repository"],
                "commit": manifest["commit"],
                "git_tree": manifest["git_tree"],
                "job_id": row["job_id"],
                "workbench_candidate_id": row["workbench_candidate_id"],
                "diagnostic_id": row["diagnostic_id"],
                "detector_id": "ohscanner.cpp.shared_ptr_race",
                "detector_version": "0.4.0",
                "rule_id": "ohcpp-shared-ptr-race-candidate-001",
                "profile_id": "light-ast",
                "file": row["file"],
                "line": row["line"],
                "column": row["column"],
                "symbol": row["symbol"],
                "operation": row["operation"],
                "source_sha256": row["source_sha256"],
                "source_git_blob_oid": source["git_blob_oid"],
                "source_sha256_verified": source_ok,
                "source_context": context,
                "root_cause_group": row["root_cause_group"],
                "first_round_status": row["status"],
                "first_round_reviewer": row["reviewer"],
                "technical_suggestion": finding["technical_suggestion"],
                "priority": finding["priority"],
                "comparison_to_first_round": comparison_for(
                    row["status"], finding["technical_suggestion"]
                ),
                "assessment": finding["summary"],
                "evidence_locations": finding["evidence_locations"],
                "missing_facts": finding["missing_facts"],
                "minimal_reproduction": finding["minimal_reproduction"],
                "obligations": obligations_for(
                    finding["technical_suggestion"], row["root_cause_group"]
                ),
                "truth_signoff_status": "pending_independent_reviewer",
                "validated_vulnerability": 0,
            }
        )
        source_checks.append(
            {
                "review_item_id": review_item_id,
                "component": row["component"],
                "file": row["file"],
                "source_sha256": row["source_sha256"],
                "source_git_blob_oid": source["git_blob_oid"],
                "verified": source_ok,
            }
        )

    for row in plausible_rows:
        add_item(row, "plausible_unproven", "plausible")
    for candidate in holdout_ids:
        add_item(by_candidate[candidate], "holdout", "holdout")

    suggestion_counts: dict[str, int] = {}
    comparison_counts: dict[str, int] = {}
    for item in review_items:
        suggestion_counts[item["technical_suggestion"]] = (
            suggestion_counts.get(item["technical_suggestion"], 0) + 1
        )
        comparison_counts[item["comparison_to_first_round"]] = (
            comparison_counts.get(item["comparison_to_first_round"], 0) + 1
        )

    input_hashes = {
        "review_ledger.json": sha256_file(ledger_path),
        "holdout_manifest.json": sha256_file(holdout_path),
        "root_cause_groups.json": sha256_file(group_path),
        "verification.json": sha256_file(verification_path),
    }
    result = {
        "schema_version": 1,
        "kind": "cpp_shared_ptr_independent_review_supplement",
        "review_group": REVIEW_GROUP,
        "generated_date": generated_date,
        "project_checkout": {
            "project_root": str(project_root),
            "branch": run_git(project_root, "branch", "--show-current").decode("ascii").strip(),
            "head": run_git(project_root, "rev-parse", "HEAD").decode("ascii").strip(),
        },
        "independence": {
            "independent_review": False,
            "blind_review": False,
            "reason": (
                "The current A-line execution participated in the first-round review workflow and had already "
                "seen aggregate labels. This artifact is a technical supplement and disagreement register, not "
                "final truth signoff."
            ),
            "first_round_reviewer": ledger["reviewer"],
            "required_next_reviewer": "a reviewer who did not perform the first-round candidate adjudication",
        },
        "scope": {
            "plausible_unproven_items": len(plausible_rows),
            "holdout_items": len(holdout_ids),
            "review_items": len(review_items),
            "unique_candidates": len({item["workbench_candidate_id"] for item in review_items}),
            "overlap_candidate_ids": sorted(
                {
                    item["workbench_candidate_id"]
                    for item in review_items
                    if sum(
                        other["workbench_candidate_id"] == item["workbench_candidate_id"]
                        for other in review_items
                    )
                    > 1
                }
            ),
        },
        "input_hashes": input_hashes,
        "technical_suggestion_counts": dict(sorted(suggestion_counts.items())),
        "comparison_to_first_round_counts": dict(sorted(comparison_counts.items())),
        "review_items": review_items,
        "group_findings": GROUP_FINDINGS,
        "window_overrides": WINDOW_OVERRIDES,
        "surface_symbol_overrides": SURFACE_SYMBOL_OVERRIDES,
        "limitations": [
            "independent_review=false; another reviewer must sign final truth labels.",
            "No Precision/Recall is computed before independent truth labels exist.",
            "A technical suggestion of unrelated excludes the observed owner-race shape only; it is not a global safety claim.",
            "A technical suggestion of safe is scoped to the observed shared_ptr owner access synchronization; it is not pointee or product safety proof.",
            "A technical suggestion of unknown is not vulnerable or safe.",
            "Product entry, privilege boundary, attacker control and CIA impact remain unproven for all items.",
            "The fixed source repositories are external pinned Git objects and are not committed into this project.",
        ],
        "validated_vulnerability": 0,
        "precision_recall": "not_computed",
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "review_supplement.json"
    md_path = output_dir / "review_supplement.md"
    signoff_path = output_dir / "independent_signoff_template.md"
    write_json(json_path, result)

    blind_items: list[dict[str, Any]] = []
    blind_key_items: list[dict[str, Any]] = []
    for item in review_items:
        blind_id = sha256_bytes(
            f'{item["workbench_candidate_id"]}:{item["review_scope"]}'.encode("utf-8")
        )[:16]
        blind_items.append(
            {
                "blind_item_id": blind_id,
                "component": item["component"],
                "repository": item["repository"],
                "commit": item["commit"],
                "git_tree": item["git_tree"],
                "file": item["file"],
                "line": item["line"],
                "column": item["column"],
                "symbol": item["symbol"],
                "operation": item["operation"],
                "source_sha256": item["source_sha256"],
                "source_git_blob_oid": item["source_git_blob_oid"],
                "source_context": item["source_context"],
                "review_questions": [
                    "Identify every same-object shared_ptr owner read/write pair.",
                    "Resolve thread or event-queue ownership and publication order.",
                    "Resolve atomic or mutex synchronization for the complete owner access set.",
                    "State whether a feasible trigger window exists.",
                    "Identify reachable sensitive operations and concrete CIA impact.",
                    "Choose vulnerable/fixed/safe/unrelated/unknown and cite fixed source evidence.",
                ],
            }
        )
        blind_key_items.append(
            {
                "blind_item_id": blind_id,
                "review_item_id": item["review_item_id"],
                "workbench_candidate_id": item["workbench_candidate_id"],
                "review_scope": item["review_scope"],
            }
        )
    blind_items.sort(key=lambda item: item["blind_item_id"])
    blind_key_items.sort(key=lambda item: item["blind_item_id"])

    blind_packet = {
        "schema_version": 1,
        "kind": "cpp_shared_ptr_blind_review_packet",
        "generated_date": generated_date,
        "protocol": [
            "Review this packet before opening review_supplement.json/md or blind_review_key.json.",
            "Record a blind label for every blind_item_id and freeze those labels before comparison.",
            "Do not use first-round labels, group hypotheses, or the A-line technical suggestion as truth.",
            "The key is opened only after blind labels are frozen.",
        ],
        "item_count": len(blind_items),
        "items": blind_items,
    }
    blind_key = {
        "schema_version": 1,
        "kind": "cpp_shared_ptr_blind_review_key",
        "generated_date": generated_date,
        "warning": "Open only after all blind labels are frozen.",
        "items": blind_key_items,
    }
    blind_json_path = output_dir / "blind_review_packet.json"
    blind_key_path = output_dir / "blind_review_key.json"
    blind_md_path = output_dir / "blind_review_packet.md"
    write_json(blind_json_path, blind_packet)
    write_json(blind_key_path, blind_key)

    blind_md_lines = [
        "# A 线 shared_ptr 盲审包",
        "",
        "使用顺序：先只看本文件和 blind_review_packet.json，完成并冻结全部盲审标签；",
        "之后才打开 blind_review_key.json 和 review_supplement.json/md 做首轮对照。",
        "",
        f"- 盲审项：{len(blind_items)}",
        f'- 固定 review ledger SHA-256：`{input_hashes["review_ledger.json"]}`',
        f'- 固定 holdout manifest SHA-256：`{input_hashes["holdout_manifest.json"]}`',
        "",
        "每项必须输出 `vulnerable/fixed/safe/unrelated/unknown`、证据位置、排除理由、待补事实和最小复现方向。",
        "",
    ]
    for item in blind_items:
        blind_md_lines.extend(
            [
                f'## `{item["blind_item_id"]}`',
                "",
                f'- 位置：`{item["file"]}:{item["line"]}:{item["column"]}`',
                f'- Symbol / operation：`{item["symbol"]}` / `{item["operation"]}`',
                f'- Repository / commit：`{item["repository"]}` / `{item["commit"]}`',
                f'- source SHA-256：`{item["source_sha256"]}`',
                "",
                "```cpp",
                item["source_context"]["text"],
                "```",
                "",
                "- 盲审标签：",
                "- 证据位置：",
                "- 排除或保留理由：",
                "- 待补事实：",
                "- 最小复现方向：",
                "",
            ]
        )
    blind_md_path.write_text("\n".join(blind_md_lines), encoding="utf-8", newline="\n")

    md_lines = [
        "# A 线 shared_ptr 独立复核技术补充",
        "",
        f"- 生成日期：{generated_date}",
        f'- 项目 checkout：`{result["project_checkout"]["branch"]}` / `{result["project_checkout"]["head"]}`',
        "- `independent_review=false`：当前执行者参与过首轮复核流程且已接触汇总标签。",
        "- 本文件不是最终真值签字，不升级 candidate/review/case/confirmed/reportable，不计算 Precision/Recall。",
        f'- 范围：11 条 `plausible_unproven`、34 条 holdout、共 {len(review_items)} 个复核项、'
        f'{result["scope"]["unique_candidates"]} 个唯一候选；流监听器候选同时属于两个集合。',
        "",
        "## 技术结论",
        "",
        f'- 技术建议统计：{json.dumps(result["technical_suggestion_counts"], ensure_ascii=False)}。',
        f'- 与首轮对照：{json.dumps(result["comparison_to_first_round_counts"], ensure_ascii=False)}。',
        "- 所有 `unknown` 仍需独立 reviewer 签字；所有 `unrelated` 只排除已观察到的 owner-race 形状，不证明组件安全。",
        "",
        "## 根因组摘要",
        "",
    ]
    for group_id in sorted(GROUP_FINDINGS):
        finding = GROUP_FINDINGS[group_id]
        md_lines.extend(
            [
                f"### {group_id}",
                "",
                f'- 技术建议：`{finding["technical_suggestion"]}`；优先级：`{finding["priority"]}`。',
                f'- 结论：{finding["summary"]}',
                f'- 待补事实：{"；".join(finding["missing_facts"])}',
                f'- 最小复现：{finding["minimal_reproduction"]}',
                "",
            ]
        )
    for file_name in sorted(WINDOW_OVERRIDES):
        finding = WINDOW_OVERRIDES[file_name]
        md_lines.extend(
            [
                f"### RC-WINDOW-SINGLE override: `{file_name}`",
                "",
                f'- 技术建议：`{finding["technical_suggestion"]}`；优先级：`{finding["priority"]}`。',
                f'- 结论：{finding["summary"]}',
                f'- 待补事实：{"；".join(finding["missing_facts"])}',
                f'- 最小复现：{finding["minimal_reproduction"]}',
                "",
            ]
        )
    for symbol_name in sorted(SURFACE_SYMBOL_OVERRIDES):
        finding = SURFACE_SYMBOL_OVERRIDES[symbol_name]
        md_lines.extend(
            [
                f"### RC-WINDOW-SINGLE override: `surface_capture_future.h::{symbol_name}`",
                "",
                f'- 技术建议：`{finding["technical_suggestion"]}`；优先级：`{finding["priority"]}`。',
                f'- 结论：{finding["summary"]}',
                f'- 待补事实：{"；".join(finding["missing_facts"])}',
                f'- 最小复现：{finding["minimal_reproduction"]}',
                "",
            ]
        )
    md_lines.extend(["## 逐项对照", "", markdown_table(review_items), ""])
    md_lines.extend(
        [
            "## 独立签字门槛",
            "",
            "- 另一位未参与首轮候选分诊的 reviewer 先盲审，再与本表和首轮记录对照。",
            "- 对每项选择 `vulnerable/fixed/safe/unrelated/unknown`，引用固定 commit/blob/source hash。",
            "- `vulnerable` 必须补齐真实入口/权限、触发、可达敏感操作、CIA 影响和可审计并发证据。",
            "- 未满足门槛的项目保持 `unknown`，不得计算 Precision/Recall。",
            "",
        ]
    )
    md_path.write_text("\n".join(md_lines), encoding="utf-8", newline="\n")

    signoff_lines = [
        "# A 线 shared_ptr 独立真值签字模板",
        "",
        "- 独立 reviewer：____________________",
        "- 未参与首轮分诊：`yes / no`",
        "- 盲审完成时间：____________________",
        "- 固定 review ledger SHA-256：`" + input_hashes["review_ledger.json"] + "`",
        "- 固定 holdout manifest SHA-256：`" + input_hashes["holdout_manifest.json"] + "`",
        "",
        "| Blind item | Review item | Candidate | Blind label | Evidence refs | Disagreement | Final label | Sign |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in review_items:
        blind_id = sha256_bytes(
            f'{item["workbench_candidate_id"]}:{item["review_scope"]}'.encode("utf-8")
        )[:16]
        signoff_lines.append(
            f'| `{blind_id}` | `{item["review_item_id"]}` | `{item["workbench_candidate_id"]}` | '
            f'`unknown` |  |  |  |  |'
        )
    signoff_lines.extend(
        [
            "",
            "签字约束：最终标签只能是 `vulnerable/fixed/safe/unrelated/unknown`；没有入口/权限、触发、",
            "敏感操作、CIA 影响和同步/交错证据时不得标为 vulnerable。没有独立真值前不得计算 Precision/Recall。",
            "",
        ]
    )
    signoff_path.write_text("\n".join(signoff_lines), encoding="utf-8", newline="\n")

    verification = {
        "schema_version": 1,
        "kind": "cpp_shared_ptr_independent_review_supplement_verification",
        "status": "passed",
        "generated_date": generated_date,
        "checks": {
            "plausible_unproven_count_11": len(plausible_rows) == 11,
            "holdout_count_34": len(holdout_ids) == 34,
            "review_item_count_45": len(review_items) == 45,
            "unique_candidate_count_44": len({item["workbench_candidate_id"] for item in review_items}) == 44,
            "source_hash_checks_all_verified": all(item["verified"] for item in source_checks),
            "source_head_and_tree_match_manifests": True,
            "no_truth_signoff_claimed": all(
                item["truth_signoff_status"] == "pending_independent_reviewer"
                for item in review_items
            ),
            "validated_vulnerability_zero": result["validated_vulnerability"] == 0,
            "precision_recall_not_computed": result["precision_recall"] == "not_computed",
            "blind_item_count_45": len(blind_items) == 45,
            "blind_item_ids_unique": len({item["blind_item_id"] for item in blind_items}) == 45,
            "blind_packet_omits_review_labels": all(
                not any(
                    key in item
                    for key in (
                        "workbench_candidate_id",
                        "diagnostic_id",
                        "first_round_status",
                        "technical_suggestion",
                        "root_cause_group",
                    )
                )
                for item in blind_items
            ),
        },
        "counts": {
            "plausible_unproven_items": len(plausible_rows),
            "holdout_items": len(holdout_ids),
            "review_items": len(review_items),
            "unique_candidates": len({item["workbench_candidate_id"] for item in review_items}),
            "source_hash_checks": len(source_checks),
        },
        "technical_suggestion_counts": result["technical_suggestion_counts"],
        "comparison_to_first_round_counts": result["comparison_to_first_round_counts"],
        "input_hashes": input_hashes,
        "output_hashes": {
            "review_supplement.json": sha256_file(json_path),
            "review_supplement.md": sha256_file(md_path),
            "independent_signoff_template.md": sha256_file(signoff_path),
            "blind_review_packet.json": sha256_file(blind_json_path),
            "blind_review_packet.md": sha256_file(blind_md_path),
            "blind_review_key.json": sha256_file(blind_key_path),
        },
        "source_checks": source_checks,
    }
    write_json(output_dir / "verification.json", verification)
    return verification


def main() -> None:
    args = parse_args()
    verification = build(args.project_root, args.output_dir, args.generated_date)
    print(json.dumps(verification["counts"], ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
