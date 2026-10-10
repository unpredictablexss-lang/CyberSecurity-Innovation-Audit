"""Build a reproducible static candidate review ledger from pinned evidence.

The module records context and provenance only. It does not adjudicate findings,
merge duplicate diagnostics, promote candidates, or perform runtime validation.
"""

import hashlib
import json
from collections import Counter

from src.benchmark.component import file_group, validate_component_report, verify_snapshot


_COVERAGE_ERROR_RULES = {
    "syntaxError", "unknownMacro", "internalError", "preprocessorErrorDirective",
}


REVIEW_FIELDS = {
    "input_control": "unknown",
    "destination_capacity": "unknown",
    "length_origin": "unknown",
    "guard_evidence": "unknown",
    "reachability": "unknown",
    "security_impact": "unknown",
    "runtime_validation": "not_run",
}

_PARTIAL_CAUSE_BY_FILE = {
    "base/include/safe_map.h": {
        "possible_causes": ["template_or_uninstantiated", "unresolved_syntax_issue"],
        "note": "Class-template assignment and dependent-name context are observed; no template instantiation was added.",
    },
    "base/include/thread_safety_analysis_macros.h": {
        "possible_causes": ["macro_expansion", "conditional_compilation", "unresolved_syntax_issue"],
        "note": "Annotation macros and a conditional extern C block are observed; annotations were not stripped or rewritten.",
    },
    "base/include/unique_fd.h": {
        "possible_causes": ["template_or_uninstantiated", "unresolved_syntax_issue"],
        "note": "Friend template comparison declarations are observed; all template paths were not instantiated.",
    },
    "base/src/ashmem.cpp": {
        "possible_causes": ["conditional_compilation", "unresolved_syntax_issue"],
        "note": "Rust/device-conditional signatures are observed; device and Rust branches remain outside the host analysis scope.",
    },
    "base/src/io_event_epoll.cpp": {
        "possible_causes": ["conditional_compilation", "unresolved_syntax_issue"],
        "note": "UTILS_FDSAN conditional branches are observed; a successful host TU does not cover the device branch.",
    },
    "base/src/parcel.cpp": {
        "possible_causes": ["member_function_pointer_or_parser_dialect", "unresolved_syntax_issue"],
        "note": "Member-function-pointer calls through this->* are observed; the AST parser remains partial in this dialect context.",
    },
    "base/test/fuzztest/parcel_fuzzer/parcel_fuzzer.cpp": {
        "possible_causes": ["macro_expansion", "unresolved_syntax_issue"],
        "note": "The operation table is macro-generated; macro definitions were not stripped to force complete parsing.",
    },
    "base/test/unittest/common/utils_thread_safety_analysis_test.cpp": {
        "possible_causes": ["macro_expansion", "unresolved_syntax_issue"],
        "note": "Thread-safety annotation/test macros are observed; annotations and test source were not modified.",
    },
}


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def source_context(root, file, line, radius=3):
    lines = (root / file).read_text(errors="replace").splitlines()
    if line is None:
        return []
    if not 1 <= line <= len(lines):
        raise ValueError("Diagnostic location is outside pinned source: " + file)
    start = max(0, line - radius - 1)
    end = min(len(lines), line + radius)
    return [dict(line=index + 1, code=lines[index]) for index in range(start, end)]


def _validate_report_contract(report, manifest, report_path, seen_paths):
    if report.get("schema_version") != 1:
        raise ValueError("Unsupported normalized report schema")
    if report_path in seen_paths:
        raise ValueError("Duplicate normalized report binding: " + str(report_path))
    required = {
        "run_id", "tool", "tool_version", "target_id", "commit", "scope_files",
        "scope_loc", "status", "diagnostics", "parsing",
    }
    missing = sorted(required - report.keys())
    if missing:
        raise ValueError("Normalized report missing fields: " + ", ".join(missing))
    validate_component_report(report, manifest)
    if report["status"] not in {"completed", "failed", "blocked"}:
        raise ValueError("Unsupported report status")
    if not report["run_id"].strip() or not report["tool"].strip():
        raise ValueError("Normalized report identity is empty")
    if not isinstance(report["diagnostics"], list) or not isinstance(report["parsing"], list):
        raise ValueError("Normalized report collections must be lists")


def _review_entry(manifest, root, report, report_path, report_sha256, item):
    if not isinstance(item, dict):
        raise ValueError("Diagnostic must be an object")
    file = item.get("file")
    if not isinstance(file, str) or not file:
        raise ValueError("Diagnostic file is required")
    known_files = {record["path"] for record in manifest["files"]}
    if file not in known_files:
        raise ValueError("Diagnostic is outside pinned snapshot: " + file)
    if file_group(file) != "production" or item.get("severity") == "note":
        raise ValueError("Only production non-note diagnostics belong in the review ledger")
    line = item.get("line")
    if line is not None and (isinstance(line, bool) or not isinstance(line, int) or line < 1):
        raise ValueError("Diagnostic line must be a positive integer or null")
    binding = "\n".join([
        manifest["repository"], manifest["commit"], manifest["tree"],
        str(report_path), report_sha256, report["run_id"],
        str(item.get("diagnostic_id", "")),
    ]).encode()
    review_id = "candidate-" + hashlib.sha256(binding).hexdigest()[:24]
    return {
        "review_entry_id": review_id,
        "candidate_status": "candidate",
        "review_status": "unassessed",
        "case_status": "draft",
        "review_origin": "automated_context_inventory",
        "review_basis": "Static diagnostic context and source excerpts only; no adjudication performed.",
        "repository": manifest["repository"],
        "commit": manifest["commit"],
        "snapshot_tree": manifest["tree"],
        "source_report_path": str(report_path),
        "source_report_sha256": report_sha256,
        "report_sha256": report_sha256,
        "tool": report["tool"],
        "tool_version": report["tool_version"],
        "run_id": report["run_id"],
        "target_id": report["target_id"],
        "report_status": report["status"],
        "report_scope_files": report["scope_files"],
        "report_scope_loc": report["scope_loc"],
        "source_location": {
            "file": file,
            "line": line,
            "column": item.get("column"),
            "symbol": item.get("symbol"),
            "rule_id": item.get("rule_id"),
            "diagnostic_id": item.get("diagnostic_id"),
        },
        "diagnostic": item,
        "source_context": source_context(root, file, line),
        **REVIEW_FIELDS,
    }


def _marker_causes(text, group):
    causes = []
    lowered = text.lower()
    if "hwtest_f" in lowered or "test_f(" in lowered or "expect_" in lowered or "assert_" in lowered:
        causes.append("macro_expansion")
    if "#if" in text or "#ifdef" in text or "defined(" in text:
        causes.append("conditional_compilation")
    if "template" in lowered or "operator=" in lowered:
        causes.append("template_or_uninstantiated")
    if "this->*" in text or "extern \"c\"" in lowered:
        causes.append("member_function_pointer_or_parser_dialect" if "this->*" in text else "macro_expansion")
    if not causes:
        causes.append("unresolved_syntax_issue")
    if group == "tests":
        causes.append("test_framework_macro_expansion")
    return list(dict.fromkeys(causes))


def _issue_causes(issues):
    if not isinstance(issues, list):
        raise ValueError("Parsing issues must be a list")
    causes = []
    for issue in issues:
        if not isinstance(issue, dict):
            raise ValueError("Parsing issue must be an object")
        kind = issue.get("kind")
        if kind == "error":
            causes.append("real_syntax_issue")
        elif kind == "missing":
            causes.append("missing_dependency_or_preprocessor_branch")
    return list(dict.fromkeys(causes))


def _partial_record(manifest, root, report, report_path, report_sha256, item):
    file = item.get("file")
    known_files = {record["path"] for record in manifest["files"]}
    if not isinstance(file, str) or file not in known_files:
        raise ValueError("Parsing record is outside pinned snapshot")
    if item.get("status") != "partial":
        raise ValueError("Only partial parsing records are classified")
    text = (root / file).read_text(errors="replace")
    configured = _PARTIAL_CAUSE_BY_FILE.get(file, {})
    issues = item.get("issues", [])
    causes = list(dict.fromkeys(
        (configured.get("possible_causes") or _marker_causes(text, file_group(file)))
        + _issue_causes(issues)
    ))
    note = configured.get("note", "Observed source constructs are candidate causes only; attribution is not proven.")
    first_line = issues[0].get("start_line") if issues else None
    return {
        "parsing_record_id": "partial-" + hashlib.sha256(
            (manifest["commit"] + "\n" + manifest["tree"] + "\n" + file + "\n" + report_sha256).encode()
        ).hexdigest()[:24],
        "repository": manifest["repository"],
        "commit": manifest["commit"],
        "snapshot_tree": manifest["tree"],
        "file": file,
        "group": file_group(file),
        "parser_status": "partial",
        "cause_status": "candidate_cause",
        "source_syntax_status": "unknown",
        "real_syntax_issue_status": "unknown",
        "attribution_status": "unassessed",
        "possible_causes": causes,
        "attribution_note": note,
        "issues": issues,
        "source_context": source_context(root, file, first_line),
        "source_report_path": str(report_path),
        "source_report_sha256": report_sha256,
        "report_sha256": report_sha256,
        "tool": report["tool"],
        "tool_version": report["tool_version"],
        "run_id": report["run_id"],
        "target_id": report["target_id"],
        "report_status": report["status"],
    }


def build_review_ledger(snapshot, report_paths, expected_report_sha256=None):
    expected_report_sha256 = expected_report_sha256 or {}
    manifest = json.loads((snapshot / "snapshot.json").read_text())
    root = snapshot / "source"
    verify_snapshot(manifest, root)
    entries, partials = [], []
    reports, seen_paths = [], set()
    for report_path in report_paths:
        report_path = report_path.resolve()
        report = json.loads(report_path.read_text())
        _validate_report_contract(report, manifest, report_path, seen_paths)
        seen_paths.add(report_path)
        digest = sha256_file(report_path)
        expected_digest = expected_report_sha256.get(str(report_path))
        if expected_digest is not None and expected_digest.lower() != digest:
            raise ValueError("Normalized report SHA-256 mismatch: " + str(report_path))
        production_candidates = 0
        for item in report["diagnostics"]:
            file = item.get("file")
            if (isinstance(file, str) and file in {record["path"] for record in manifest["files"]}
                    and file_group(file) == "production" and item.get("severity") != "note"
                    and item.get("rule_id") not in _COVERAGE_ERROR_RULES):
                production_candidates += 1
        reports.append({
            "source_report_path": str(report_path),
            "source_report_sha256": digest,
            "tool": report["tool"],
            "tool_version": report["tool_version"],
            "run_id": report["run_id"],
            "target_id": report["target_id"],
            "report_status": report["status"],
            "scope_files": report["scope_files"],
            "scope_loc": report["scope_loc"],
            "diagnostic_count": len(report["diagnostics"]),
            "parsing_count": len(report["parsing"]),
            "production_review_count": production_candidates,
            "partial_parsing_count": sum(item.get("status") != "complete" for item in report["parsing"]),
            "limitations": report.get("limitations", []),
        })
        for item in report["diagnostics"]:
            file = item.get("file")
            if not isinstance(file, str) or file not in {record["path"] for record in manifest["files"]}:
                raise ValueError("Diagnostic is outside pinned snapshot: " + str(file))
            if file_group(file) != "production" or item.get("severity") == "note":
                continue
            if item.get("rule_id") in _COVERAGE_ERROR_RULES:
                continue
            entries.append(_review_entry(manifest, root, report, report_path, digest, item))
        for item in report["parsing"]:
            if item.get("status") != "complete":
                partials.append(_partial_record(manifest, root, report, report_path, digest, item))

    return {
        "schema_version": 1,
        "experiment_kind": "current_component",
        "repository": manifest["repository"],
        "commit": manifest["commit"],
        "snapshot_tree": manifest["tree"],
        "review_status": "unassessed",
        "case_status": "draft",
        "validated_vulnerability": 0,
        "runtime_validation": "not_run",
        "review_entries": entries,
        "partial_parsing": partials,
        "source_reports": reports,
        "counts": {
            "review_entries": len(entries),
            "partial_parsing": len(partials),
            "partial_production": sum(item["group"] == "production" for item in partials),
            "partial_tests": sum(item["group"] == "tests" for item in partials),
            "review_entries_by_tool": dict(sorted(Counter(item["tool"] for item in entries).items())),
            "partial_parsing_by_group": dict(sorted(Counter(item["group"] for item in partials).items())),
        },
        "interpretation": (
            "Context and provenance ledger only. Every diagnostic remains an unassessed candidate; "
            "partial parsing remains partial and duplicate diagnostics are retained."
        ),
    }


def render_review_markdown(ledger):
    lines = [
        "# c_utils 固定版本候选上下文审查账本",
        "",
        "> 自动生成的静态上下文与证据绑定记录。所有条目为 candidate / unassessed / draft；"
        "不合并重复诊断，不计算漏洞数，不做动态验证。",
        "",
        f"- repository: `{ledger['repository']}`",
        f"- commit: `{ledger['commit']}`",
        f"- snapshot tree: `{ledger['snapshot_tree']}`",
        f"- review entries: {ledger['counts']['review_entries']}",
        f"- partial parsing: {ledger['counts']['partial_parsing']} "
        f"(production {ledger['counts']['partial_production']} / tests {ledger['counts']['partial_tests']})",
        f"- validated vulnerability: 0",
        "",
        "## 生产代码候选",
        "",
        "| entry | tool | run status | source | rule | candidate / review / case | "
        "input_control | destination_capacity | length_origin | guard_evidence | "
        "reachability | security_impact | runtime_validation | source report | source report SHA-256 |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for item in ledger["review_entries"]:
        loc = item["source_location"]
        source = f"{loc['file']}:{loc['line'] or 'unknown'}"
        rule = loc["rule_id"] or "unknown"
        state = f"{item['candidate_status']} / {item['review_status']} / {item['case_status']}"
        lines.append("| " + " | ".join([
            item["review_entry_id"], item["tool"], item["report_status"], source, rule, state,
            item["input_control"], item["destination_capacity"], item["length_origin"],
            item["guard_evidence"], item["reachability"], item["security_impact"],
            item["runtime_validation"], item["source_report_path"], "`" + item["source_report_sha256"] + "`",
        ]) + " |")
    lines += ["", "## 候选源码上下文", ""]
    for item in ledger["review_entries"]:
        location = item["source_location"]
        lines += [
            "### " + item["review_entry_id"],
            "",
            f"- tool/run: `{item['tool']}` / `{item['run_id']}` ({item['report_status']})",
            f"- source report: `{item['source_report_path']}`",
            f"- source report SHA-256: `{item['source_report_sha256']}`",
            f"- source location: `{location['file']}:{location['line'] or 'unknown'}`"
            f":{location['column'] or 'unknown'}",
            f"- rule: `{location['rule_id'] or 'unknown'}`",
            "",
        ]
        for line in item["source_context"]:
            lines.append(f"    {line['line']} | {line['code']}")
        lines.append("")
    lines += [
        "",
        "## AST 部分解析归因候选",
        "",
        "| record | group | file | parser | cause status | source syntax | possible causes | source report SHA-256 |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for item in ledger["partial_parsing"]:
        lines.append("| " + " | ".join([
            item["parsing_record_id"], item["group"], item["file"], item["parser_status"],
            item["cause_status"], item["source_syntax_status"], ", ".join(item["possible_causes"]),
            "`" + item["source_report_sha256"] + "`",
        ]) + " |")
    lines += ["", "## Partial 归因说明", ""]
    for item in ledger["partial_parsing"]:
        lines += [
            f"- `{item['file']}`: {item['attribution_note']} "
            f"possible_causes={','.join(item['possible_causes'])}; "
            f"syntax={item['source_syntax_status']}; issues={len(item['issues'])}.",
        ]
    lines += ["", "## 覆盖限制", "",
        "设备路径、Rust、ashmem/设备条件分支、测试代码和未实例化模板未作为完整分析覆盖。"
        "失败或部分解析保持 unknown；未执行扫描器不记 miss。", ""]
    return "\n".join(lines)
