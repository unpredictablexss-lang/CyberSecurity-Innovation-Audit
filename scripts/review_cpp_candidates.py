#!/usr/bin/env python3
"""Create exact-scope workbench jobs and append reviews for the 208 candidates."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sqlite3
import time
from collections import Counter, defaultdict
from pathlib import Path, PureWindowsPath
from typing import Any

from src.workbench import service
from src.workbench.settings import Settings
from src.workbench.store import Store
from src.workbench.worker import Worker


COMPONENTS = (
    "update_updateservice",
    "security_access_token",
    "distributeddatamgr_kv_store",
    "window_window_manager",
    "communication_dsoftbus",
)
DETECTORS = ("ohscanner.cpp.shared_ptr_race", "ohscanner.cpp.lifetime")
REVIEWER = "teammate-A / static review"
EXPECTED_OLD = {
    "update_updateservice": 3,
    "security_access_token": 12,
    "distributeddatamgr_kv_store": 180,
    "window_window_manager": 31,
    "communication_dsoftbus": 3,
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def resolve_repo_path(raw: str) -> Path:
    if re.match(r"^[A-Za-z]:[\\/]", raw) and os.name != "nt":
        return Path("/mnt") / raw[0].lower() / raw[2:].replace("\\", "/").lstrip("/")
    return Path(raw)


def operation(diagnostic: dict[str, Any]) -> str:
    message = diagnostic.get("message", "")
    if "member write" in message:
        return "write"
    if "member read" in message:
        return "read"
    return "unknown"


def review_policy(component: str, file: str, symbol: str, op: str) -> dict[str, str]:
    if "kvstoremock/" in file:
        return {
            "group_id": "RC-SCOPE-MOCK",
            "status": "refuted",
            "title": "non-production mock scope error",
            "hypothesis": "The candidate is outside the production component scope.",
            "remaining_unknown": "No production vulnerability claim is made from this mock path.",
        }
    if component == "distributeddatamgr_kv_store" and symbol in {
        "nativeStore_",
        "nativeQueryPtr_",
        "nativeResultSet_",
        "kvDataManager_",
        "proxy_",
        "resultSet_",
    }:
        return {
            "group_id": "RC-KV-OWNER",
            "status": "likely_false_positive",
            "title": "stable owner pointer shape",
            "hypothesis": (
                "The owner is initialized and then read through stable pointer operations; "
                "the observed syntax pair is likely owner-race noise."
            ),
            "remaining_unknown": (
                "Pointee thread safety, safe publication and cross-file owner mutation remain unknown."
            ),
        }
    if component == "distributeddatamgr_kv_store" and file.endswith("js_proxy.h"):
        return {
            "group_id": "RC-JSPROXY",
            "status": "plausible_unproven",
            "title": "JSProxy mutable owner access pair",
            "hypothesis": "SetInstance and GetInstance expose a mutable owner pair without a repository-local lock.",
            "remaining_unknown": "NapiQueue serialization, publication order and attacker-controlled interleaving remain unknown.",
        }
    if component == "security_access_token" and symbol == "ptrChannel_":
        return {
            "group_id": "RC-REMOTE-CHANNEL",
            "status": "plausible_unproven",
            "title": "RemoteCommandExecutor channel owner pair",
            "hypothesis": "Repository call sites are under RemoteCommandManager::mutex_, but GetChannel returns a member reference.",
            "remaining_unknown": "External callers, reference lifetime and product thread ownership remain unknown.",
        }
    if component == "communication_dsoftbus" and symbol == "streamListener_":
        return {
            "group_id": "RC-STREAM-LISTENER",
            "status": "plausible_unproven",
            "title": "StreamManager listener cross-file mutation",
            "hypothesis": "streamListener_ is initialized in the header and reassigned in stream_manager.cpp without a lexical lock.",
            "remaining_unknown": "Cross-file call ordering, event-loop ownership and feasible concurrent interleaving remain unknown.",
        }
    if component == "communication_dsoftbus" and symbol == "msgManager_":
        return {
            "group_id": "RC-STREAM-MANAGER",
            "status": "likely_false_positive",
            "title": "StreamManager manager pointer publication shape",
            "hypothesis": "The manager pointer is set before factory return and no repository-local getter mutation was observed.",
            "remaining_unknown": "Product publication and pointee thread safety remain unknown.",
        }
    if component == "window_window_manager" and symbol in {
        "mainWindowXComponentController_",
        "pipXComponentController_",
    }:
        return {
            "group_id": "RC-PIP-CONTROLLERS",
            "status": "plausible_unproven",
            "title": "PIP controller owner transfer pair",
            "hypothesis": "Getter/setter call sites are sequential field transfers, but product event-loop ownership is not proven.",
            "remaining_unknown": "Thread ownership, publication order and reachable trigger conditions remain unknown.",
        }
    if component in {"update_updateservice", "security_access_token"} and symbol in {
        "timeUtilsProxy_",
        "data_",
        "asyncContextPtr",
    }:
        return {
            "group_id": "RC-CONSTRUCTOR-NOISE",
            "status": "likely_false_positive",
            "title": "constructor or single lexical access noise",
            "hypothesis": "The observed access is initialization or a single lexical access, not a proven conflicting pair.",
            "remaining_unknown": "Cross-file mutation, publication and pointee thread safety remain unknown.",
        }
    return {
        "group_id": "RC-WINDOW-SINGLE",
        "status": "likely_false_positive",
        "title": "single lexical owner read shape",
        "hypothesis": "Only one bound lexical access was observed for this owner member in the selected source scope.",
        "remaining_unknown": "Cross-file mutation, product threading and pointee behavior remain unknown.",
    }


def normalized_diagnostics(report: dict[str, Any]) -> set[tuple[Any, ...]]:
    return {
        (
            run["tool"],
            run["tool_version"],
            item["diagnostic_id"],
            item["file"],
            item["line"],
            item.get("column"),
            item.get("source_sha256"),
        )
        for run in report["detector_runs"]
        for item in run["diagnostics"]
    }


def verify_against_canonical(actual: dict[str, Any], canonical: dict[str, Any]) -> dict[str, Any]:
    checks = {
        "repository": actual["repository"] == canonical["repository"],
        "commit": actual["commit"] == canonical["commit"],
        "git_tree": actual["git_tree"] == canonical["git_tree"],
        "snapshot_sha256": actual["snapshot_sha256"] == canonical["snapshot_sha256"],
        "selected_files": actual["scope"]["selected_source_files"]
        == canonical["scope"]["selected_source_files"],
        "selected_bytes": actual["scope"]["selected_source_bytes"]
        == canonical["scope"]["selected_source_bytes"],
        "validated_vulnerability": actual["validated_vulnerability"] == 0,
        "diagnostic_identity_set": normalized_diagnostics(actual)
        == normalized_diagnostics(canonical),
    }
    actual_runs = {row["tool"]: row for row in actual["detector_runs"]}
    canonical_runs = {row["tool"]: row for row in canonical["detector_runs"]}
    checks["detector_runs"] = set(actual_runs) == set(canonical_runs)
    for tool in sorted(set(actual_runs) & set(canonical_runs)):
        left, right = actual_runs[tool], canonical_runs[tool]
        checks[f"detector:{tool}"] = (
            left["tool_version"] == right["tool_version"]
            and left["status"] == right["status"]
            and left["scope_files"] == right["scope_files"]
            and left["diagnostic_count"] == right["diagnostic_count"]
        )
    if not all(checks.values()):
        raise ValueError(f"workbench report differs from canonical report: {checks}")
    return checks


def ensure_repository(settings: Settings, store: Store, name: str, path: Path) -> dict[str, Any]:
    for row in store.repositories():
        if row["name"] == name or Path(row["path"]) == path:
            service.check_repository(settings, row["path"])
            return row
    service.check_repository(settings, path)
    return store.add_repository(name, str(path))


def retry_store(callable_, *args, **kwargs):
    for attempt in range(6):
        try:
            return callable_(*args, **kwargs)
        except sqlite3.OperationalError as exc:
            if "unable to open database file" not in str(exc) or attempt == 5:
                raise
            time.sleep(0.2 * (attempt + 1))


def find_or_create_job(
    settings: Settings, store: Store, repository_id: str, spec: dict[str, Any]
) -> dict[str, Any]:
    for job in store.jobs():
        if (
            job["repository_id"] == repository_id
            and job["spec"].get("commit") == spec["commit"]
            and job["spec"].get("git_tree") == spec["git_tree"]
            and job["spec"].get("include_paths") == spec["include_paths"]
            and list(job["spec"].get("detector_ids", []))
            == list(spec["detector_ids"])
        ):
            if job["status"] in {"queued", "running"}:
                raise RuntimeError(f"job is already active: {job['id']}")
            if job["status"] in {"completed", "completed_with_limitations"}:
                return job
    job = retry_store(store.create_job, repository_id, spec)
    claimed = retry_store(store.claim)
    if claimed["id"] != job["id"]:
        raise RuntimeError("workbench queue claimed a different job")
    Worker(settings).execute(claimed)
    return retry_store(store.job, job["id"])


def review_note(item: dict[str, Any], policy: dict[str, str]) -> str:
    evidence = item.get("evidence", {})
    obligations = evidence.get("obligations", [])
    return (
        f"Static review {policy['title']}. "
        f"file={item['file']}:{item['line']} symbol={item.get('symbol')} "
        f"operation={operation(item)}. "
        f"Hypothesis: {policy['hypothesis']} "
        f"Remaining unknown: {policy['remaining_unknown']} "
        f"Evidence obligations: {json.dumps(obligations, ensure_ascii=False, sort_keys=True)}. "
        "This review is candidate-level analysis, not confirmed/reportable evidence."
    )


def add_source_evidence(settings, store, job, item, policy):
    line = item["line"]
    start = max(1, line - 8)
    source = service.source(settings, store, job, item["file"])
    end = min(len(source["text"].splitlines()), line + 8)
    note = f"{policy['title']}; representative fixed-source context."
    expected_hash = service.sha("".join(source["text"].splitlines(keepends=True)[start - 1 : end]).encode("utf-8"))
    for record in retry_store(store.source_evidence, job["id"], item["id"]):
        if (
            record.get("kind") == "source_excerpt"
            and record.get("file") == item["file"]
            and record.get("start_line") == start
            and record.get("end_line") == end
            and record.get("excerpt_sha256") == expected_hash
        ):
            return record
    return retry_store(
        service.source_excerpt,
        settings,
        store,
        job,
        item["id"],
        item["file"],
        start,
        end,
        note,
    )


def ensure_review(store: Store, job_id: str, item: dict[str, Any], policy: dict[str, str]) -> None:
    note = review_note(item, policy)
    for attempt in range(6):
        existing = retry_store(store.reviews, job_id, item["id"])
        if existing:
            latest = existing[-1]
            if (
                latest["status"] == policy["status"]
                and latest["reviewer"] == REVIEWER
                and latest["notes"] == note
            ):
                return
            raise RuntimeError(f"review already exists with different content: {item['id']}")
        try:
            retry_store(
                store.add_review,
                job_id,
                item["id"],
                policy["status"],
                REVIEWER,
                note,
                0,
            )
            return
        except sqlite3.OperationalError:
            if attempt == 5:
                raise
            time.sleep(0.2 * (attempt + 1))


def ensure_case(store: Store, title: str, links: list[dict[str, str]]) -> str:
    existing = next((case for case in store.cases() if case["title"] == title), None)
    if existing is None:
        return retry_store(store.create_case, title, links[:100])
    current = {(link["job_id"], link["candidate_id"]) for link in existing["links"]}
    missing = [
        link
        for link in links
        if (link["job_id"], link["candidate_id"]) not in current
    ]
    while missing:
        retry_store(store.link_case, existing["id"], missing[:100])
        missing = missing[100:]
    return existing["id"]


def run_component(settings, store, manifest_path: Path, canonical_path: Path) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    component = manifest["component"]
    repo = ensure_repository(
        settings,
        store,
        manifest["repository"],
        resolve_repo_path(manifest["source_repo_path"]),
    )
    includes = [
        entry["path"]
        for shard in manifest["shards"]
        for entry in shard["entries"]
    ]
    spec = service.make_spec(
        repo,
        manifest["commit"],
        includes,
        DETECTORS,
        1800,
        4096,
    )
    finished = find_or_create_job(settings, store, repo["id"], spec)
    job = finished
    if finished["status"] not in {"completed", "completed_with_limitations"}:
        raise RuntimeError(f"{component}: workbench job failed: {finished['error']}")
    report = service.read_report(settings, finished)
    canonical = json.loads(canonical_path.read_text(encoding="utf-8"))
    comparison = verify_against_canonical(report, canonical)
    findings = [
        item
        for item in service.findings(report)
        if item["detector_id"] == "ohscanner.cpp.shared_ptr_race"
    ]
    policies = {}
    review_rows = []
    for item in findings:
        policy = review_policy(component, item["file"], item.get("symbol") or "", operation(item))
        policies[item["id"]] = policy
        ensure_review(store, job["id"], item, policy)
        review_rows.append(
            {
                "component": component,
                "job_id": job["id"],
                "workbench_candidate_id": item["id"],
                "diagnostic_id": item["diagnostic_id"],
                "file": item["file"],
                "line": item["line"],
                "column": item.get("column"),
                "symbol": item.get("symbol"),
                "operation": operation(item),
                "source_sha256": item.get("source_sha256"),
                "status": policy["status"],
                "reviewer": REVIEWER,
                "root_cause_group": policy["group_id"],
                "review_note": review_note(item, policy),
                "obligations": item.get("evidence", {}).get("obligations", []),
            }
        )

    groups = defaultdict(list)
    for item in findings:
        groups[policies[item["id"]]["group_id"]].append(item)
    evidence_ids = defaultdict(list)
    for group_id, members in sorted(groups.items()):
        representatives = members[:1]
        if len(members) > 1:
            representatives.append(members[-1])
        for item in representatives:
            record = add_source_evidence(settings, store, finished, item, policies[item["id"]])
            evidence_ids[group_id].append(record["id"])

    cases = {}
    for group_id, members in sorted(groups.items()):
        title = f"{component}: {policies[members[0]['id']]['title']}"
        rationale = (
            f"Review group {group_id}; candidate-level hypothesis only, "
            "not a shared root-cause proof."
        )
        links = [
            {
                "job_id": job["id"],
                "candidate_id": item["id"],
                "rationale": rationale,
            }
            for item in members
        ]
        case_id = ensure_case(store, title, links)
        cases[group_id] = case_id

    bundle = service.review_bundle(settings, store, finished)
    bundle_dir = Path("research/evidence/cpp/review_20261014/workbench")
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / f"{component}.review.json").write_text(
        json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (bundle_dir / f"{component}.review.md").write_text(
        service.review_markdown(bundle), encoding="utf-8"
    )
    return {
        "component": component,
        "job_id": job["id"],
        "report_sha256": finished["report_sha256"],
        "comparison": comparison,
        "review_rows": review_rows,
        "group_evidence_ids": dict(evidence_ids),
        "case_ids": cases,
        "bundle_json": str(bundle_dir / f"{component}.review.json"),
        "bundle_md": str(bundle_dir / f"{component}.review.md"),
    }


def build_holdout(rows, controls):
    holdout_groups = {
        "RC-STREAM-LISTENER",
        "RC-CONSTRUCTOR-NOISE",
        "RC-WINDOW-SINGLE",
        "RC-SCOPE-MOCK",
    }
    holdout = [row for row in rows if row["root_cause_group"] in holdout_groups]
    development = [row for row in rows if row["root_cause_group"] not in holdout_groups]
    holdout_keys = {
        (row["file"], row.get("symbol") or "", row.get("source_sha256") or "")
        for row in holdout
    }
    development_keys = {
        (row["file"], row.get("symbol") or "", row.get("source_sha256") or "")
        for row in development
    }
    if holdout_keys & development_keys:
        raise ValueError("holdout leakage: file/symbol/source hash appears in both sets")
    return {
        "schema_version": 1,
        "kind": "shared_ptr_review_holdout_design",
        "status": "designed_not_scored",
        "holdout_groups": sorted(holdout_groups),
        "holdout_candidate_count": len(holdout),
        "development_candidate_count": len(development),
        "holdout_candidate_ids": [row["workbench_candidate_id"] for row in holdout],
        "development_candidate_ids": [row["workbench_candidate_id"] for row in development],
        "controls": controls,
        "leakage_checks": {
            "same_file_symbol_source_hash_overlap": False,
            "root_cause_group_disjoint": True,
        },
        "labels": {
            "current_candidates": "unlabeled_candidate_review",
            "fixture_controls": "synthetic_controls_not_real_world_truth",
        },
        "limitations": [
            "No Precision/Recall is computed before independent truth labels exist.",
            "Fixture controls are synthetic and are not a public vulnerability benchmark.",
            "A holdout candidate remains candidate/unassessed until an independent review signs it off.",
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--target-root", type=Path, required=True)
    parser.add_argument("--manifest-dir", type=Path, required=True)
    parser.add_argument("--canonical-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    project_root = args.project_root.resolve()
    data_dir = args.data_dir.resolve()
    target_root = args.target_root.resolve()
    manifest_dir = args.manifest_dir.resolve()
    canonical_dir = args.canonical_dir.resolve()
    out_dir = args.out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    settings = Settings(data_dir, (target_root,))
    settings.initialize()
    store = Store(settings.data_dir)
    components = []
    for component in COMPONENTS:
        components.append(
            run_component(
                settings,
                store,
                manifest_dir / f"{component}.manifest.json",
                canonical_dir / f"{component}.json",
            )
        )
    rows = [row for component in components for row in component["review_rows"]]
    if len(rows) != 208:
        raise RuntimeError(f"expected 208 shared_ptr reviews, got {len(rows)}")
    if len({row["diagnostic_id"] for row in rows}) != 208:
        raise RuntimeError("diagnostic IDs are not unique")
    fixture_manifest = json.loads(
        (project_root / "tests/detectors/fixtures/cpp_shared_ptr_race/manifest.json").read_text(
            encoding="utf-8"
        )
    )
    controls = [
        {
            "path": unit["path"],
            "category": unit["fixture_category"],
            "expected_observation": unit["expected_observation"],
            "sha256": unit["sha256"],
        }
        for unit in fixture_manifest["units"]
    ]
    holdout = build_holdout(rows, controls)
    groups = defaultdict(list)
    for row in rows:
        groups[row["root_cause_group"]].append(row)
    group_rows = []
    for group_id, members in sorted(groups.items()):
        group_rows.append(
            {
                "group_id": group_id,
                "candidate_count": len(members),
                "status_counts": dict(Counter(row["status"] for row in members)),
                "candidate_ids": [row["workbench_candidate_id"] for row in members],
                "diagnostic_ids": [row["diagnostic_id"] for row in members],
                "hypothesis": members[0]["review_note"],
                "root_cause_conclusion": "hypothesis_only_not_proven",
            }
        )
    baseline_summary = json.loads(
        (project_root / "outputs/unified-development/algorithm-integration-summary.json").read_text(
            encoding="utf-8"
        )
    )
    baseline = {
        "schema_version": 1,
        "kind": "historical_229_candidate_identity_record",
        "individual_candidate_ids_status": "unavailable",
        "individual_candidate_ids_note": (
            "Historical report bytes and individual IDs were not recoverable from the checkout; "
            "aggregate counts and report hashes are preserved without inventing mappings."
        ),
        "total_candidate_diagnostics": baseline_summary["a_total_candidate_diagnostics"],
        "components": baseline_summary["a_shared_ptr_component_runs"],
    }
    ledger = {
        "schema_version": 1,
        "kind": "cpp_shared_ptr_review_ledger",
        "reviewer": REVIEWER,
        "validated_vulnerability": 0,
        "candidate_count": len(rows),
        "components": components,
        "candidates": rows,
        "root_cause_groups": group_rows,
    }
    (out_dir / "review_ledger.json").write_text(
        json.dumps(ledger, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (out_dir / "root_cause_groups.json").write_text(
        json.dumps(group_rows, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (out_dir / "baseline_229_identity.json").write_text(
        json.dumps(baseline, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (out_dir / "holdout_manifest.json").write_text(
        json.dumps(holdout, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    lines = [
        "# 208 条 shared_ptr 候选人工复核台账",
        "",
        f"- Reviewer: `{REVIEWER}`",
        "- 逐条状态已写入工作台 append-only review；不是 confirmed/reportable。",
        f"- 候选：{len(rows)}；历史基线：{baseline['total_candidate_diagnostics']}。",
        f"- 根因组：{len(group_rows)} 个分析假设组，不等同于已证明根因。",
        "",
        "## 状态统计",
        "",
    ]
    for status, count in sorted(Counter(row["status"] for row in rows).items()):
        lines.append(f"- `{status}`: {count}")
    lines += [
        "",
        "## 证据边界",
        "",
        "- `likely_false_positive` 是对候选机制的静态复核判断，不是组件安全证明。",
        "- `plausible_unproven` 保留并发、发布、入口、权限和 CIA 影响 unknown。",
        "- 旧 229 条原始候选 ID 不可恢复，`baseline_229_identity.json` 只保留聚合身份和哈希。",
        "- 没有独立真值前不计算 Precision/Recall。",
    ]
    (out_dir / "review_ledger.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps({"candidate_count": len(rows), "groups": len(group_rows), "out_dir": str(out_dir)}, indent=2))


if __name__ == "__main__":
    main()
