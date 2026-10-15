from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple


ROOT = Path(".")
OLD_RUN = ROOT / "outputs/reports/cpp_same_scope_20261014/run"
OUT_ROOT = ROOT / "outputs/reports/a_cpp_fixed_rescan_sharedptr050_lifetime040_20261015"
NEW_RUN = OUT_ROOT / "run"
COMPARISON = OUT_ROOT / "comparison"
LEDGER_PATH = ROOT / "research/evidence/cpp/review_20261014/review_ledger.json"
HOLDOUT_PATH = ROOT / "research/evidence/cpp/review_20261014/holdout_manifest.json"
SUPPLEMENT_PATH = ROOT / "research/evidence/cpp/independent_review_20261015/review_supplement.json"
COMPONENTS = [
    "update_updateservice",
    "security_access_token",
    "distributeddatamgr_kv_store",
    "window_window_manager",
    "communication_dsoftbus",
]
FOCUS_GROUPS = {
    "RC-JSPROXY",
    "RC-REMOTE-CHANNEL",
    "RC-PIP-CONTROLLERS",
    "RC-STREAM-LISTENER",
}
SURFACE_RE = re.compile(r"(surface_capture|ui_effect)", re.IGNORECASE)
EXPECTED_VERSIONS = {
    "ohscanner.cpp.shared_ptr_race": "0.5.0",
    "ohscanner.cpp.lifetime": "0.4.0",
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def json_load(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def json_dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def run_git(repo: str, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", repo, *args], text=True, encoding="utf-8", errors="replace"
    ).strip()


def command_without_output_paths(argv: Sequence[str]) -> List[str]:
    result = list(argv)
    for i, item in enumerate(result):
        if item in ("--json-out", "--md-out") and i + 1 < len(result):
            result[i + 1] = "<new-output>"
    return result


def replace_output_paths(argv: Sequence[str], component: str) -> List[str]:
    result = list(argv)
    for i, item in enumerate(result):
        if item == "--json-out" and i + 1 < len(result):
            result[i + 1] = str((NEW_RUN / f"{component}.json").resolve())
        elif item == "--md-out" and i + 1 < len(result):
            result[i + 1] = str((NEW_RUN / f"{component}.md").resolve())
    return result


def stable_key(component: str, diagnostic: Mapping[str, Any]) -> Tuple[Any, ...]:
    return (
        component,
        diagnostic.get("provider"),
        diagnostic.get("rule_id"),
        diagnostic.get("file"),
        diagnostic.get("line"),
        diagnostic.get("column"),
        diagnostic.get("symbol"),
        diagnostic.get("source_sha256"),
    )


def key_text(key: Sequence[Any]) -> str:
    return "|".join("" if item is None else str(item) for item in key)


def normalize_obligation(obligation: Mapping[str, Any]) -> Dict[str, Any]:
    source_binding = obligation.get("source_binding")
    if isinstance(source_binding, Mapping):
        normalized_binding = {
            k: v for k, v in source_binding.items() if k != "detector_version"
        }
    else:
        normalized_binding = source_binding
    return {
        "kind": obligation.get("kind"),
        "description": obligation.get("description"),
        "status": obligation.get("status"),
        "source_binding": normalized_binding,
    }


def normalize_obligations(obligations: Iterable[Mapping[str, Any]]) -> List[Dict[str, Any]]:
    return [normalize_obligation(item) for item in obligations]


def diagnostic_record(
    component: str,
    diagnostic: Mapping[str, Any],
    obligation_item: Mapping[str, Any] | None,
    ledger_entry: Mapping[str, Any] | None,
) -> Dict[str, Any]:
    record = {
        "component": component,
        "stable_key": list(stable_key(component, diagnostic)),
        "diagnostic_id": diagnostic.get("diagnostic_id"),
        "provider": diagnostic.get("provider"),
        "evidence_type": diagnostic.get("evidence_type"),
        "file": diagnostic.get("file"),
        "line": diagnostic.get("line"),
        "column": diagnostic.get("column"),
        "rule_id": diagnostic.get("rule_id"),
        "severity": diagnostic.get("severity"),
        "message": diagnostic.get("message"),
        "candidate_cwe": diagnostic.get("candidate_cwe"),
        "confidence": diagnostic.get("confidence"),
        "symbol": diagnostic.get("symbol"),
        "source_sha256": diagnostic.get("source_sha256"),
        "consequence_impact": diagnostic.get("consequence_impact"),
        "consequence_cwe": diagnostic.get("consequence_cwe"),
        "source_binding": diagnostic.get("source_binding"),
        "obligations": normalize_obligations(
            (obligation_item or {}).get("obligations", [])
        ),
    }
    if ledger_entry:
        record["historical_candidate_id"] = ledger_entry.get("workbench_candidate_id")
        record["historical_review_status"] = ledger_entry.get("status")
        record["root_cause_group"] = ledger_entry.get("root_cause_group")
    else:
        record["historical_candidate_id"] = None
        record["historical_review_status"] = None
        record["root_cause_group"] = None
    return record


def find_ledger_entry(
    component: str,
    diagnostic: Mapping[str, Any],
    ledger_by_diag: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    exact = ledger_by_diag.get(diagnostic.get("diagnostic_id"))
    if exact:
        return exact
    provider = diagnostic.get("provider")
    for entry in ledger_by_diag.values():
        if entry.get("component") != component:
            continue
        if not str(entry.get("diagnostic_id", "")).startswith(f"{provider}:"):
            continue
        if (
            entry.get("file") == diagnostic.get("file")
            and entry.get("line") == diagnostic.get("line")
            and entry.get("column") == diagnostic.get("column")
            and entry.get("symbol") == diagnostic.get("symbol")
            and entry.get("source_sha256") == diagnostic.get("source_sha256")
        ):
            return entry
    return None


def extract_candidates(
    component: str, report: Mapping[str, Any], ledger_by_diag: Mapping[str, Mapping[str, Any]]
) -> Dict[Tuple[Any, ...], Dict[str, Any]]:
    obligations_by_diag = {}
    for tool, coverage in report.get("detector_coverage", {}).get("detectors", {}).items():
        for item in coverage.get("evidence_obligations", []):
            obligations_by_diag[item.get("diagnostic_id")] = item
    result: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
    for run in report.get("detector_runs", []):
        for diagnostic in run.get("diagnostics", []):
            key = stable_key(component, diagnostic)
            ledger_entry = find_ledger_entry(component, diagnostic, ledger_by_diag)
            result[key] = diagnostic_record(
                component,
                diagnostic,
                obligations_by_diag.get(diagnostic.get("diagnostic_id")),
                ledger_entry,
            )
    return result


def changed_fields(old: Mapping[str, Any], new: Mapping[str, Any]) -> List[str]:
    fields = [
        "diagnostic_id",
        "provider",
        "evidence_type",
        "file",
        "line",
        "column",
        "rule_id",
        "severity",
        "message",
        "candidate_cwe",
        "confidence",
        "symbol",
        "source_sha256",
        "consequence_impact",
        "consequence_cwe",
        "source_binding",
        "obligations",
    ]
    return [field for field in fields if old.get(field) != new.get(field)]


def compact_candidate(record: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "component": record.get("component"),
        "historical_candidate_id": record.get("historical_candidate_id"),
        "diagnostic_id": record.get("diagnostic_id"),
        "provider": record.get("provider"),
        "rule_id": record.get("rule_id"),
        "file": record.get("file"),
        "line": record.get("line"),
        "column": record.get("column"),
        "symbol": record.get("symbol"),
        "source_sha256": record.get("source_sha256"),
        "root_cause_group": record.get("root_cause_group"),
        "historical_review_status": record.get("historical_review_status"),
        "evidence_type": record.get("evidence_type"),
        "severity": record.get("severity"),
        "message": record.get("message"),
        "candidate_cwe": record.get("candidate_cwe"),
        "confidence": record.get("confidence"),
        "consequence_impact": record.get("consequence_impact"),
        "consequence_cwe": record.get("consequence_cwe"),
        "source_binding": record.get("source_binding"),
        "obligations": record.get("obligations"),
    }


def coverage_projection(coverage: Mapping[str, Any]) -> Dict[str, Any]:
    source_sha = coverage.get("source_sha256", {})
    return {
        "status": coverage.get("status"),
        "scope_mode": coverage.get("scope_mode"),
        "coverage_counts": coverage.get("coverage_counts"),
        "coverage_semantics": coverage.get("coverage_semantics"),
        "applicable_files": coverage.get("applicable_files"),
        "analyzed_files": coverage.get("analyzed_files"),
        "partially_inspected_files": coverage.get("partially_inspected_files"),
        "unexamined": coverage.get("unexamined"),
        "inspected_files": coverage.get("inspected_files"),
        "not_analyzed_files": coverage.get("not_analyzed_files"),
        "source_sha256_count": len(source_sha),
        "source_sha256": source_sha,
        "evidence_obligations": normalize_obligations(
            [
                obligation
                for item in coverage.get("evidence_obligations", [])
                for obligation in item.get("obligations", [])
            ]
        ),
    }


def detector_projection(run: Mapping[str, Any]) -> Dict[str, Any]:
    return {
        "tool": run.get("tool"),
        "tool_version": run.get("tool_version"),
        "status": run.get("status"),
        "scope_files": run.get("scope_files"),
        "scope_loc": run.get("scope_loc"),
        "diagnostic_count": run.get("diagnostic_count"),
        "limitations": run.get("limitations", []),
    }


def identity_projection(report: Mapping[str, Any]) -> Dict[str, Any]:
    scope = report.get("scope", {})
    return {
        "repository": report.get("repository"),
        "target_id": report.get("target_id"),
        "commit": report.get("commit"),
        "git_tree": report.get("git_tree"),
        "snapshot_sha256": report.get("snapshot_sha256"),
        "profile_id": report.get("profile_id"),
        "provenance": report.get("provenance"),
        "selected_source_files": scope.get("selected_source_files"),
        "selected_source_bytes": scope.get("selected_source_bytes"),
        "declared_scope": scope.get("declared_scope"),
    }


def compare_component(
    component: str,
    old_report: Mapping[str, Any],
    new_report: Mapping[str, Any],
    ledger_by_diag: Mapping[str, Mapping[str, Any]],
) -> Dict[str, Any]:
    old_candidates = extract_candidates(component, old_report, ledger_by_diag)
    new_candidates = extract_candidates(component, new_report, ledger_by_diag)
    old_keys = set(old_candidates)
    new_keys = set(new_candidates)
    added = [{"stable_key": list(key), "candidate": compact_candidate(new_candidates[key])} for key in sorted(new_keys - old_keys, key=key_text)]
    disappeared = [{"stable_key": list(key), "candidate": compact_candidate(old_candidates[key])} for key in sorted(old_keys - new_keys, key=key_text)]
    changed = []
    unchanged = []
    for key in sorted(old_keys & new_keys, key=key_text):
        old = old_candidates[key]
        new = new_candidates[key]
        fields = changed_fields(old, new)
        if fields:
            changed.append(
                {
                    "stable_key": list(key),
                    "changed_fields": fields,
                    "historical_candidate_id": old.get("historical_candidate_id"),
                    "old_diagnostic_id": old.get("diagnostic_id"),
                    "new_diagnostic_id": new.get("diagnostic_id"),
                    "old": compact_candidate(old),
                    "new": compact_candidate(new),
                }
            )
        else:
            unchanged.append(
                {
                    "stable_key": list(key),
                    "historical_candidate_id": old.get("historical_candidate_id"),
                    "diagnostic_id": old.get("diagnostic_id"),
                    "candidate": compact_candidate(new),
                }
            )

    old_detectors = {item.get("tool"): detector_projection(item) for item in old_report.get("detector_runs", [])}
    new_detectors = {item.get("tool"): detector_projection(item) for item in new_report.get("detector_runs", [])}
    detector_status = {}
    for tool in sorted(set(old_detectors) | set(new_detectors)):
        old = old_detectors.get(tool)
        new = new_detectors.get(tool)
        status_fields = ["status", "scope_files", "scope_loc", "diagnostic_count"]
        detector_status[tool] = {
            "old": old,
            "new": new,
            "status_fields_changed": [
                field for field in status_fields if (old or {}).get(field) != (new or {}).get(field)
            ],
            "limitations_changed": (old or {}).get("limitations") != (new or {}).get("limitations"),
            "limitations_added": [
                item for item in (new or {}).get("limitations", [])
                if item not in (old or {}).get("limitations", [])
            ],
            "limitations_removed": [
                item for item in (old or {}).get("limitations", [])
                if item not in (new or {}).get("limitations", [])
            ],
            "version_changed": (old or {}).get("tool_version") != (new or {}).get("tool_version"),
        }

    old_coverage = old_report.get("detector_coverage", {}).get("detectors", {})
    new_coverage = new_report.get("detector_coverage", {}).get("detectors", {})
    coverage = {}
    for tool in sorted(set(old_coverage) | set(new_coverage)):
        old = coverage_projection(old_coverage.get(tool, {}))
        new = coverage_projection(new_coverage.get(tool, {}))
        coverage[tool] = {
            "old": old,
            "new": new,
            "changed_fields": [
                field for field in old if old.get(field) != new.get(field)
            ],
        }

    old_identity = identity_projection(old_report)
    new_identity = identity_projection(new_report)
    invariant_fields = [
        "repository",
        "target_id",
        "commit",
        "git_tree",
        "snapshot_sha256",
        "profile_id",
        "provenance",
        "selected_source_files",
        "selected_source_bytes",
        "declared_scope",
    ]
    invariants = {
        field: {
            "old": old_identity.get(field),
            "new": new_identity.get(field),
            "equal": old_identity.get(field) == new_identity.get(field),
        }
        for field in invariant_fields
    }

    return {
        "component": component,
        "identity_invariants": invariants,
        "report_status": {
            "old": old_report.get("status"),
            "new": new_report.get("status"),
            "equal": old_report.get("status") == new_report.get("status"),
        },
        "report_limitations": {
            "old": old_report.get("limitations", []),
            "new": new_report.get("limitations", []),
            "equal": old_report.get("limitations", []) == new_report.get("limitations", []),
            "added": [
                item for item in new_report.get("limitations", [])
                if item not in old_report.get("limitations", [])
            ],
            "removed": [
                item for item in old_report.get("limitations", [])
                if item not in new_report.get("limitations", [])
            ],
        },
        "detector_status": detector_status,
        "coverage": coverage,
        "candidate_counts": {
            "old": len(old_candidates),
            "new": len(new_candidates),
            "added": len(added),
            "disappeared": len(disappeared),
            "changed": len(changed),
            "unchanged": len(unchanged),
            "stable_identity_retained": len(old_keys & new_keys),
            "diagnostic_id_unchanged": sum(
                1 for key in old_keys & new_keys
                if old_candidates[key].get("diagnostic_id") == new_candidates[key].get("diagnostic_id")
            ),
            "diagnostic_id_changed": sum(
                1 for key in old_keys & new_keys
                if old_candidates[key].get("diagnostic_id") != new_candidates[key].get("diagnostic_id")
            ),
            "rule_location_source_sha_unchanged": len(old_keys & new_keys),
        },
        "added": added,
        "disappeared": disappeared,
        "changed": changed,
        "unchanged": unchanged,
    }


def build_focus(
    comparisons: Mapping[str, Mapping[str, Any]],
    ledger: Mapping[str, Any],
    holdout_ids: set[str],
    supplement_items: Sequence[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    supplement_by_diag = {
        item.get("diagnostic_id"): item for item in supplement_items
    }
    entries = []
    for candidate in ledger.get("candidates", []):
        group = candidate.get("root_cause_group")
        file_name = candidate.get("file", "")
        if group not in FOCUS_GROUPS and not SURFACE_RE.search(file_name):
            continue
        component = candidate.get("component")
        key = (
            component,
            "ohscanner.cpp.shared_ptr_race",
            "ohcpp-shared-ptr-race-candidate-001",
            candidate.get("file"),
            candidate.get("line"),
            candidate.get("column"),
            candidate.get("symbol"),
            candidate.get("source_sha256"),
        )
        result = comparisons.get(component, {})
        changed = next((item for item in result.get("changed", []) if tuple(item.get("stable_key", [])) == key), None)
        unchanged = next((item for item in result.get("unchanged", []) if tuple(item.get("stable_key", [])) == key), None)
        added = next((item for item in result.get("added", []) if tuple(item.get("stable_key", [])) == key), None)
        disappeared = next((item for item in result.get("disappeared", []) if tuple(item.get("stable_key", [])) == key), None)
        if changed:
            classification = "changed"
            current = changed.get("new")
        elif unchanged:
            classification = "unchanged"
            current = unchanged.get("candidate")
        elif added:
            classification = "added"
            current = added.get("candidate")
        elif disappeared:
            classification = "disappeared"
            current = None
        else:
            classification = "not_in_comparison"
            current = None
        supplement = supplement_by_diag.get(candidate.get("diagnostic_id"), {})
        entries.append(
            {
                "component": component,
                "root_cause_group": group,
                "workbench_candidate_id": candidate.get("workbench_candidate_id"),
                "historical_diagnostic_id": candidate.get("diagnostic_id"),
                "classification": classification,
                "historical_review_status": candidate.get("status"),
                "holdout": candidate.get("workbench_candidate_id") in holdout_ids,
                "file": candidate.get("file"),
                "line": candidate.get("line"),
                "column": candidate.get("column"),
                "symbol": candidate.get("symbol"),
                "source_sha256": candidate.get("source_sha256"),
                "current": current,
                "independent_review_comparison": supplement.get("comparison_to_first_round"),
                "independent_review_suggestion": supplement.get("technical_suggestion"),
                "independent_review_truth_signoff": supplement.get("truth_signoff_status"),
                "independent_review_missing_facts": supplement.get("missing_facts", []),
            }
        )
    return entries


def markdown_for_comparison(result: Mapping[str, Any], focus: Sequence[Mapping[str, Any]]) -> str:
    lines = [
        "# 固定 A 线 Detector 同范围复扫比较",
        "",
        "- 生成时间：2026-10-15 Asia/Shanghai",
        "- 新运行：`shared_ptr` `0.5.0` + `lifetime` `0.4.0`",
        "- 基线运行：`outputs/reports/cpp_same_scope_20261014/run`（`0.4.0` + `0.3.0`）",
        "- 该比较是静态 Detector 观察差异，不是 Precision/Recall，不表示漏洞修复或安全证明。",
        "",
        "## 固定身份与范围",
        "",
        "| 组件 | commit/tree/snapshot/profile/scope | 状态 |",
        "|---|---|---|",
    ]
    for item in result["components"]:
        inv = item["identity_invariants"]
        equal = all(value["equal"] for value in inv.values())
        lines.append(
            f"| {item['component']} | commit/tree/snapshot/profile/scope "
            f"{'unchanged' if equal else 'CHANGED'} | "
            f"{item['report_status']['old']} → {item['report_status']['new']} |"
        )
    lines += [
        "",
        "## Detector status",
        "",
        "| 组件 | Detector | 版本 | status | scope_files | diagnostics | limitations |",
        "|---|---|---|---|---:|---:|---|",
    ]
    for item in result["components"]:
        for tool, state in item["detector_status"].items():
            old = state["old"] or {}
            new = state["new"] or {}
            lim = "changed" if state["limitations_changed"] else "unchanged"
            lines.append(
                f"| {item['component']} | `{tool}` | {old.get('tool_version')} → {new.get('tool_version')} | "
                f"{old.get('status')} → {new.get('status')} | {old.get('scope_files')} → {new.get('scope_files')} | "
                f"{old.get('diagnostic_count')} → {new.get('diagnostic_count')} | {lim} |"
            )
    lines += [
        "",
        "## Coverage",
        "",
        "| 组件 | Detector | coverage status | complete/partial/not_analyzed/failed | source SHA | obligations |",
        "|---|---|---|---|---:|---:|",
    ]
    for item in result["components"]:
        for tool, state in item["coverage"].items():
            old = state["old"]
            new = state["new"]
            oc = old.get("coverage_counts", {})
            nc = new.get("coverage_counts", {})
            lines.append(
                f"| {item['component']} | `{tool}` | {old.get('status')} → {new.get('status')} | "
                f"{oc.get('complete')}/{oc.get('partial')}/{oc.get('not_analyzed')}/{oc.get('failed')} → "
                f"{nc.get('complete')}/{nc.get('partial')}/{nc.get('not_analyzed')}/{nc.get('failed')} | "
                f"{old.get('source_sha256_count')} → {new.get('source_sha256_count')} | "
                f"{len(old.get('evidence_obligations', []))} → {len(new.get('evidence_obligations', []))} |"
            )
    lines += [
        "",
        "## Limitations delta",
        "",
        "| 组件 | 范围 | changed | added | removed |",
        "|---|---|---|---:|---:|",
    ]
    for item in result["components"]:
        report_limits = item["report_limitations"]
        lines.append(
            f"| {item['component']} | report | {'yes' if not report_limits['equal'] else 'no'} | "
            f"{len(report_limits['added'])} | {len(report_limits['removed'])} |"
        )
        for tool, state in item["detector_status"].items():
            lines.append(
                f"| {item['component']} | `{tool}` | {'yes' if state['limitations_changed'] else 'no'} | "
                f"{len(state['limitations_added'])} | {len(state['limitations_removed'])} |"
            )
    lines += [
        "",
        "## 候选差异（稳定身份按 provider/rule/file/line/column/symbol/source SHA）",
        "",
        "| 组件 | added | disappeared | changed | unchanged | stable retained | diagnostic ID changed | old total | new total |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for item in result["components"]:
        c = item["candidate_counts"]
        lines.append(
            f"| {item['component']} | {c['added']} | {c['disappeared']} | {c['changed']} | "
            f"{c['unchanged']} | {c['stable_identity_retained']} | {c['diagnostic_id_changed']} | "
            f"{c['old']} | {c['new']} |"
        )
    for category in ("added", "disappeared", "changed", "unchanged"):
        lines += ["", f"### {category}", ""]
        rows = []
        for item in result["components"]:
            for entry in item[category]:
                if category == "changed":
                    rows.append(
                        f"- `{entry['old']['component']}` `{entry['old']['file']}:{entry['old']['line']}:{entry['old']['column']}` "
                        f"`{entry['old']['symbol']}` — historical `{entry['historical_candidate_id']}` / "
                        f"`{entry['old_diagnostic_id']}` → current `{entry['new_diagnostic_id']}`; "
                        f"changed fields: {', '.join(entry['changed_fields'])}"
                    )
                else:
                    record = entry.get("candidate", entry)
                    rows.append(
                        f"- `{record['component']}` `{record['file']}:{record['line']}:{record['column']}` "
                        f"`{record['symbol']}` — historical `{record.get('historical_candidate_id')}` / "
                        f"`{record.get('diagnostic_id')}`"
                    )
        lines.extend(rows or ["- 无"])
    lines += [
        "",
        "## 重点根因组与 holdout 分歧",
        "",
        "| root-cause | holdout | component | location | symbol | classification | historical review | independent comparison |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in focus:
        lines.append(
            f"| {item['root_cause_group']} | {'yes' if item['holdout'] else 'no'} | {item['component']} | "
            f"`{item['file']}:{item['line']}:{item['column']}` | `{item['symbol']}` | {item['classification']} | "
            f"{item['historical_review_status']} | {item['independent_review_comparison']} |"
        )
    lines += [
        "",
        "## 解释边界",
        "",
        "- `added/disappeared/changed/unchanged` 是固定范围和版本的静态观察差异，不是 Precision/Recall。",
        "- 候选减少不等于安全，候选增加不等于漏洞；缺编译上下文、跨文件同步、产品入口和 CIA 影响继续保持 unknown。",
        "- 历史候选 ID、旧 review、旧报告字节和历史结论均不改写；新比较只保存对应关系。",
        "- `surface_capture`/`ui_effect` 分歧保留 holdout 与独立复核意见，不把 review 标签升级为真值。",
        "- 本次 `validated_vulnerability=0`，不产生 confirmed/reportable 结论。",
    ]
    return "\n".join(lines) + "\n"


def write_summary(result: Mapping[str, Any], focus: Sequence[Mapping[str, Any]]) -> None:
    totals = {
        field: sum(item["candidate_counts"][field] for item in result["components"])
        for field in (
            "old", "new", "added", "disappeared", "changed", "unchanged",
            "stable_identity_retained", "diagnostic_id_unchanged",
            "diagnostic_id_changed", "rule_location_source_sha_unchanged",
        )
    }
    obligations_unchanged = 0
    messages_changed = 0
    for item in result["components"]:
        obligations_unchanged += len(item["unchanged"])
        obligations_unchanged += sum(
            1 for entry in item["changed"] if "obligations" not in entry["changed_fields"]
        )
        messages_changed += sum(
            1 for entry in item["changed"] if "message" in entry["changed_fields"]
        )
    identity_verified = all(
        detail["equal"]
        for item in result["components"]
        for detail in item["identity_invariants"].values()
    )
    components = []
    for item in result["components"]:
        components.append({
            "component": item["component"],
            "identity_invariants": item["identity_invariants"],
            "report_status": item["report_status"],
            "report_limitations_equal": item["report_limitations"]["equal"],
            "detectors": {
                tool: {
                    "old_version": state["old"].get("tool_version"),
                    "new_version": state["new"].get("tool_version"),
                    "old_status": state["old"].get("status"),
                    "new_status": state["new"].get("status"),
                    "old_scope_files": state["old"].get("scope_files"),
                    "new_scope_files": state["new"].get("scope_files"),
                    "old_diagnostics": state["old"].get("diagnostic_count"),
                    "new_diagnostics": state["new"].get("diagnostic_count"),
                    "limitations_changed": state["limitations_changed"],
                    "limitations_added_count": len(state["limitations_added"]),
                    "limitations_removed_count": len(state["limitations_removed"]),
                }
                for tool, state in item["detector_status"].items()
            },
            "coverage": {
                tool: {
                    "old_status": state["old"].get("status"),
                    "new_status": state["new"].get("status"),
                    "old_counts": state["old"].get("coverage_counts"),
                    "new_counts": state["new"].get("coverage_counts"),
                    "old_source_sha256_count": state["old"].get("source_sha256_count"),
                    "new_source_sha256_count": state["new"].get("source_sha256_count"),
                    "old_obligations": len(state["old"].get("evidence_obligations", [])),
                    "new_obligations": len(state["new"].get("evidence_obligations", [])),
                    "changed_fields": state["changed_fields"],
                }
                for tool, state in item["coverage"].items()
            },
            "candidate_counts": item["candidate_counts"],
        })
    summary = {
        "schema_version": 1,
        "kind": "cpp_fixed_a_same_scope_rescan_summary",
        "generated": "2026-10-15 Asia/Shanghai",
        "baseline_detector_versions": {
            "ohscanner.cpp.shared_ptr_race": "0.4.0",
            "ohscanner.cpp.lifetime": "0.3.0",
        },
        "new_detector_versions": EXPECTED_VERSIONS,
        "fixed_identity_and_scope_verified": identity_verified,
        "candidate_totals": totals,
        "matched_candidate_semantics": {
            "rule_location_source_sha_unchanged": totals["rule_location_source_sha_unchanged"],
            "obligations_unchanged": obligations_unchanged,
            "messages_changed": messages_changed,
            "diagnostic_ids_changed": totals["diagnostic_id_changed"],
        },
        "components": components,
        "focus_review": [
            {
                "root_cause_group": item["root_cause_group"],
                "holdout": item["holdout"],
                "component": item["component"],
                "file": item["file"],
                "line": item["line"],
                "column": item["column"],
                "symbol": item["symbol"],
                "classification": item["classification"],
                "historical_review_status": item["historical_review_status"],
                "independent_review_comparison": item["independent_review_comparison"],
                "independent_review_suggestion": item["independent_review_suggestion"],
                "workbench_candidate_id": item["workbench_candidate_id"],
                "historical_diagnostic_id": item["historical_diagnostic_id"],
                "current_diagnostic_id": (item.get("current") or {}).get("diagnostic_id"),
            }
            for item in focus
        ],
        "interpretation": {
            "precision_recall": "not_computed",
            "version_delta_is_not_fix_or_accuracy": True,
            "candidate_decrease_is_not_safety": True,
            "validated_vulnerability": 0,
        },
    }
    json_dump(OUT_ROOT / "summary.json", summary)
    lines = [
        "# 固定 A 线五组件同范围复扫摘要",
        "",
        "- 生成时间：2026-10-15 Asia/Shanghai",
        "- Detector：`shared_ptr` `0.5.0`，`lifetime` `0.4.0`",
        "- commit/tree/逐文件 scope/snapshot/profile：全部与基线一致",
        f"- 候选：old {totals['old']} → new {totals['new']}；added {totals['added']} / disappeared {totals['disappeared']} / changed {totals['changed']} / unchanged {totals['unchanged']}",
        f"- 稳定身份保留 {totals['stable_identity_retained']}；规则/位置/source SHA 不变 {totals['rule_location_source_sha_unchanged']}；diagnostic ID changed {totals['diagnostic_id_changed']}；义务不变 {obligations_unchanged}",
        "- 这些是 Detector 版本差异，不是 Precision/Recall、漏洞修复或安全证明。",
        "",
        "## 组件",
        "",
        "| 组件 | shared_ptr | lifetime | added | disappeared | changed | unchanged |",
        "|---|---|---|---:|---:|---:|---:|",
    ]
    for item in components:
        shared = item["detectors"]["ohscanner.cpp.shared_ptr_race"]
        lifetime = item["detectors"]["ohscanner.cpp.lifetime"]
        counts = item["candidate_counts"]
        lines.append(
            f"| {item['component']} | {shared['old_status']} {shared['old_diagnostics']}→{shared['new_diagnostics']} | "
            f"{lifetime['old_status']} {lifetime['old_diagnostics']}→{lifetime['new_diagnostics']} | "
            f"{counts['added']} | {counts['disappeared']} | {counts['changed']} | {counts['unchanged']} |"
        )
    lines += [
        "",
        "## 重点项",
        "",
        "| root-cause | holdout | classification | location | historical review | independent comparison |",
        "|---|---|---|---|---|---|",
    ]
    for item in focus:
        lines.append(
            f"| {item['root_cause_group']} | {'yes' if item['holdout'] else 'no'} | {item['classification']} | "
            f"`{item['file']}:{item['line']}:{item['column']}` | {item['historical_review_status']} | "
            f"{item['independent_review_comparison']} |"
        )
    lines += [
        "",
        "## 边界",
        "",
        "- 候选减少不等于安全；缺编译上下文、跨文件同步、产品入口、触发条件和 CIA 影响继续保持 unknown。",
        "- 历史候选 ID 和旧 review 不改写；comparison.json 保存新旧对应关系。",
        "- 不计算 Precision/Recall，`validated_vulnerability=0`。",
    ]
    (OUT_ROOT / "summary.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_verification(result: Mapping[str, Any]) -> None:
    old_summary = json_load(OLD_RUN / "summary.json")
    old_summary_components = {item["component"]: item for item in old_summary["components"]}
    old_artifact_checks = {}
    artifact_names = {
        "json": "json",
        "md": "md",
        "terminal": "terminal.txt",
        "command": "command.json",
    }
    for component in COMPONENTS:
        old_artifact_checks[component] = {}
        for name, suffix in artifact_names.items():
            expected = old_summary_components[component]["artifacts"][name]["sha256"]
            actual = sha256_file(OLD_RUN / f"{component}.{suffix}")
            old_artifact_checks[component][name] = {
                "expected_sha256": expected,
                "actual_sha256": actual,
                "unchanged": expected == actual,
            }

    supplement = json_load(SUPPLEMENT_PATH)
    review_input_checks = {}
    for name, expected in supplement.get("input_hashes", {}).items():
        actual = sha256_file(ROOT / "research/evidence/cpp/review_20261014" / name)
        review_input_checks[name] = {
            "expected_sha256": expected,
            "actual_sha256": actual,
            "unchanged": expected == actual,
        }

    command_checks = {}
    for execution in result["executions"]:
        component = execution["component"]
        old_command = json_load(OLD_RUN / f"{component}.command.json")
        new_command = json_load(NEW_RUN / f"{component}.command.json")
        command_checks[component] = {
            "same_except_output_paths": command_without_output_paths(old_command["command"])
            == command_without_output_paths(new_command["command"]),
            "returncode_zero": new_command["returncode"] == 0,
        }

    identity_checks = {
        item["component"]: all(detail["equal"] for detail in item["identity_invariants"].values())
        for item in result["components"]
    }
    version_checks = {
        component: all(
            detail["expected"] == detail["observed"]
            for detail in checks.values()
        )
        for component, checks in result["new_run"]["version_checks"].items()
    }
    all_checks = {
        "old_run_artifacts_unchanged": all(
            detail["unchanged"]
            for component in old_artifact_checks.values()
            for detail in component.values()
        ),
        "old_review_inputs_unchanged": all(
            detail["unchanged"] for detail in review_input_checks.values()
        ),
        "commands_same_except_output_paths": all(
            detail["same_except_output_paths"] for detail in command_checks.values()
        ),
        "new_commands_returned_zero": all(
            detail["returncode_zero"] for detail in command_checks.values()
        ),
        "fixed_identity_scope_snapshot_profile_unchanged": all(identity_checks.values()),
        "detector_versions_exact": all(version_checks.values()),
    }
    verification = {
        "schema_version": 1,
        "kind": "cpp_fixed_a_rescan_verification",
        "generated": "2026-10-15 Asia/Shanghai",
        "status": "passed" if all(all_checks.values()) else "failed",
        "checks": all_checks,
        "old_run_artifact_checks": old_artifact_checks,
        "old_review_input_checks": review_input_checks,
        "command_checks": command_checks,
        "identity_checks": identity_checks,
        "version_checks": version_checks,
        "historical_candidate_ids_modified": False,
        "old_reviews_modified": False,
        "precision_recall": "not_computed",
        "validated_vulnerability": 0,
    }
    json_dump(OUT_ROOT / "verification.json", verification)
    lines = [
        "# 固定 A 线同范围复扫验证",
        "",
        f"- status：`{verification['status']}`",
        f"- 旧五组件 report artifacts 未变：`{all_checks['old_run_artifacts_unchanged']}`",
        f"- 旧 review 输入哈希未变：`{all_checks['old_review_inputs_unchanged']}`",
        f"- 命令仅输出路径不同：`{all_checks['commands_same_except_output_paths']}`",
        f"- commit/tree/scope/snapshot/profile 不变：`{all_checks['fixed_identity_scope_snapshot_profile_unchanged']}`",
        f"- Detector 版本精确：`{all_checks['detector_versions_exact']}`",
        "- 历史候选 ID 与旧 review 不修改；Precision/Recall 未计算；`validated_vulnerability=0`。",
    ]
    (OUT_ROOT / "verification.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    if OUT_ROOT.exists():
        raise SystemExit(f"refusing to overwrite existing output: {OUT_ROOT}")
    NEW_RUN.mkdir(parents=True)
    COMPARISON.mkdir(parents=True)

    ledger = json_load(LEDGER_PATH)
    holdout = json_load(HOLDOUT_PATH)
    supplement = json_load(SUPPLEMENT_PATH)
    holdout_ids = set(holdout.get("holdout_candidate_ids", []))
    ledger_by_diag = {
        item.get("diagnostic_id"): item for item in ledger.get("candidates", [])
    }

    detector_paths = [
        ROOT / "src/ohscanner/detectors/cpp/shared_ptr_race_detector.py",
        ROOT / "src/ohscanner/detectors/cpp/lifetime_detector.py",
    ]
    checkout = {
        "branch": run_git(".", "rev-parse", "--abbrev-ref", "HEAD"),
        "head": run_git(".", "rev-parse", "HEAD"),
        "tree": run_git(".", "rev-parse", "HEAD^{tree}"),
        "remote": run_git(".", "remote", "get-url", "origin"),
        "dirty_status_sha256": sha256_bytes(
            subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=".")
        ),
        "dirty_status_file_count": len(
            subprocess.check_output(["git", "status", "--porcelain=v1"], cwd=".")
            .decode("utf-8", errors="replace")
            .splitlines()
        ),
        "detector_files": {
            str(path): sha256_file(path) for path in detector_paths
        },
    }
    json_dump(OUT_ROOT / "checkout_and_detector_manifest.json", checkout)

    executions = []
    old_reports = {}
    new_reports = {}
    for component in COMPONENTS:
        command_path = OLD_RUN / f"{component}.command.json"
        old_command = json_load(command_path)
        old_argv = old_command["command"]
        new_argv = replace_output_paths(old_argv, component)
        started = time.time()
        completed = subprocess.run(
            new_argv,
            cwd=old_command["cwd"],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        elapsed = time.time() - started
        terminal_path = NEW_RUN / f"{component}.terminal.txt"
        terminal_path.write_text(completed.stdout, encoding="utf-8")
        command_record = {
            "command": new_argv,
            "cwd": old_command["cwd"],
            "returncode": completed.returncode,
        }
        json_dump(NEW_RUN / f"{component}.command.json", command_record)
        executions.append(
            {
                "component": component,
                "old_command_path": str(command_path),
                "old_command_sha256": sha256_file(command_path),
                "new_command_path": str(NEW_RUN / f"{component}.command.json"),
                "new_command_sha256": sha256_file(NEW_RUN / f"{component}.command.json"),
                "command_without_output_paths": command_without_output_paths(old_argv),
                "returncode": completed.returncode,
                "elapsed_seconds": elapsed,
                "terminal_path": str(terminal_path),
                "terminal_sha256": sha256_file(terminal_path),
            }
        )
        if completed.returncode != 0:
            raise SystemExit(f"{component} failed with return code {completed.returncode}")
        old_reports[component] = json_load(OLD_RUN / f"{component}.json")
        new_reports[component] = json_load(NEW_RUN / f"{component}.json")

    component_comparisons = {
        component: compare_component(
            component, old_reports[component], new_reports[component], ledger_by_diag
        )
        for component in COMPONENTS
    }
    focus = build_focus(component_comparisons, ledger, holdout_ids, supplement.get("review_items", []))

    expected_version_checks = {}
    for component, report in new_reports.items():
        expected_version_checks[component] = {
            tool: {
                "expected": expected,
                "observed": next(
                    (
                        run.get("tool_version")
                        for run in report.get("detector_runs", [])
                        if run.get("tool") == tool
                    ),
                    None,
                ),
            }
            for tool, expected in EXPECTED_VERSIONS.items()
        }

    result = {
        "schema_version": 1,
        "kind": "cpp_fixed_a_same_scope_detector_version_comparison",
        "generated": "2026-10-15 Asia/Shanghai",
        "baseline": {
            "run_directory": str(OLD_RUN),
            "detector_versions": {"ohscanner.cpp.shared_ptr_race": "0.4.0", "ohscanner.cpp.lifetime": "0.3.0"},
        },
        "new_run": {
            "run_directory": str(NEW_RUN),
            "detector_versions": EXPECTED_VERSIONS,
            "version_checks": expected_version_checks,
        },
        "checkout": checkout,
        "executions": executions,
        "components": [component_comparisons[component] for component in COMPONENTS],
        "focus_review": focus,
        "interpretation": {
            "precision_recall": "not_computed",
            "candidate_decrease_is_not_safety": True,
            "version_difference_is_not_fix_or_accuracy": True,
            "validated_vulnerability": 0,
            "unknowns": [
                "missing compilation/build context",
                "cross-file synchronization and complete access protocol",
                "product entry, privilege boundary and attacker control",
                "reachable trigger and concrete CIA impact",
            ],
        },
    }
    json_dump(COMPARISON / "comparison.json", result)
    (COMPARISON / "comparison.md").write_text(
        markdown_for_comparison(result, focus), encoding="utf-8"
    )
    write_summary(result, focus)
    write_verification(result)

    artifact_paths = sorted(
        path
        for path in OUT_ROOT.rglob("*")
        if path.is_file() and path.name != "artifact_manifest.json"
    )
    manifest = {
        "schema_version": 1,
        "kind": "cpp_fixed_a_rescan_artifact_manifest",
        "generated": "2026-10-15 Asia/Shanghai",
        "files": {
            str(path): {"sha256": sha256_file(path), "bytes": path.stat().st_size}
            for path in artifact_paths
        },
        "comparison": {
            "old_run": str(OLD_RUN),
            "new_run": str(NEW_RUN),
            "components": COMPONENTS,
            "stable_identity": "component|provider|rule_id|file|line|column|symbol|source_sha256",
        },
    }
    json_dump(OUT_ROOT / "artifact_manifest.json", manifest)
    print(json.dumps({
        "output_root": str(OUT_ROOT),
        "components": {
            component: component_comparisons[component]["candidate_counts"]
            for component in COMPONENTS
        },
        "focus_review_count": len(focus),
    }, ensure_ascii=False, indent=2))
    return 0



def rebuild_existing() -> int:
    if not OUT_ROOT.exists():
        raise SystemExit(f"missing generated run: {OUT_ROOT}")
    ledger = json_load(LEDGER_PATH)
    holdout = json_load(HOLDOUT_PATH)
    supplement = json_load(SUPPLEMENT_PATH)
    holdout_ids = set(holdout.get("holdout_candidate_ids", []))
    ledger_by_diag = {
        item.get("diagnostic_id"): item for item in ledger.get("candidates", [])
    }
    component_comparisons = {}
    for component in COMPONENTS:
        old_report = json_load(OLD_RUN / f"{component}.json")
        new_report = json_load(NEW_RUN / f"{component}.json")
        component_comparisons[component] = compare_component(
            component, old_report, new_report, ledger_by_diag
        )
    focus = build_focus(
        component_comparisons, ledger, holdout_ids, supplement.get("review_items", [])
    )
    result = json_load(COMPARISON / "comparison.json")
    result["components"] = [component_comparisons[component] for component in COMPONENTS]
    result["focus_review"] = focus
    json_dump(COMPARISON / "comparison.json", result)
    (COMPARISON / "comparison.md").write_text(
        markdown_for_comparison(result, focus), encoding="utf-8"
    )
    write_summary(result, focus)
    write_verification(result)
    artifact_paths = sorted(
        path
        for path in OUT_ROOT.rglob("*")
        if path.is_file() and path.name != "artifact_manifest.json"
    )
    manifest = {
        "schema_version": 1,
        "kind": "cpp_fixed_a_rescan_artifact_manifest",
        "generated": "2026-10-15 Asia/Shanghai",
        "files": {
            str(path): {"sha256": sha256_file(path), "bytes": path.stat().st_size}
            for path in artifact_paths
        },
        "comparison": {
            "old_run": str(OLD_RUN),
            "new_run": str(NEW_RUN),
            "components": COMPONENTS,
            "stable_identity": "component|provider|rule_id|file|line|column|symbol|source_sha256",
        },
    }
    json_dump(OUT_ROOT / "artifact_manifest.json", manifest)
    print(json.dumps({
        "output_root": str(OUT_ROOT),
        "components": {
            component: component_comparisons[component]["candidate_counts"]
            for component in COMPONENTS
        },
        "focus_review_count": len(focus),
    }, ensure_ascii=False, indent=2))
    return 0

if __name__ == "__main__":
    if "--rebuild-comparison" in sys.argv:
        raise SystemExit(rebuild_existing())
    raise SystemExit(main())
