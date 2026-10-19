"""Reconcile D50 Pasteboard parse coverage with current and unnormalized replay."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import tree_sitter_cpp
from tree_sitter import Language, Parser

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from src.parser.ast import parse_source
from src.parser.syntax_normalize import normalize_member_pointer_syntax


COMMIT = "dd22c7cb5e5f207a6c38c50f45b7369ee8575840"
TREE = "e374a0d61c9ec664ddd29fc17002797828c480ee"


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args])


def node_diagnostics(data, normalize):
    parser = Parser(Language(tree_sitter_cpp.language()))
    parser_input = normalize_member_pointer_syntax(data) if normalize else data
    root = parser.parse(parser_input).root_node
    issues = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.is_error or node.is_missing:
            excerpt = data[node.start_byte:node.end_byte].decode("utf-8", "replace")[:160]
            issues.append({
                "kind": "missing" if node.is_missing else "error",
                "node_type": node.type,
                "start_line": node.start_point.row + 1,
                "start_column": node.start_point.column + 1,
                "end_line": node.end_point.row + 1,
                "end_column": node.end_point.column + 1,
                "parent_type": node.parent.type if node.parent else None,
                "source_excerpt": excerpt,
            })
        stack.extend(reversed(node.children))
    return ("partial" if root.has_error else "complete"), issues


def load_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", type=Path, required=True)
    parser.add_argument("--d50-report", type=Path, default=Path("research/data_sensitive/D50_COMPONENT_CVE_REPLAY/pasteboard.json"))
    parser.add_argument("--d68-report", type=Path, default=Path("research/evidence/cpp/D68_PASTEBOARD_RAW67_REPLAY_20261023.json"))
    parser.add_argument("--output", type=Path, default=Path("research/evidence/cpp/D67_PASTEBOARD_PARSE_AUDIT_20261023.json"))
    args = parser.parse_args()

    baseline = load_json(args.d50_report)
    current = load_json(args.d68_report)
    if baseline["commit"] != COMMIT or baseline["git_tree"] != TREE:
        raise SystemExit("D50 source identity differs from the frozen task input")
    actual_tree = git(args.repo_dir, "rev-parse", f"{COMMIT}^{{tree}}").decode().strip()
    if actual_tree != TREE:
        raise SystemExit("source checkout tree does not match D50")

    baseline_rows = {row["file"]: row for row in baseline["detector_runs"][0]["parsing"]}
    current_rows = {row["file"]: row for row in current["detector_runs"][0]["parsing"]}
    baseline_hashes = baseline["detector_coverage"]["detectors"]["ohscanner.known_disclosed_cves"]["source_sha256"]
    current_hashes = current["detector_coverage"]["detectors"]["ohscanner.known_disclosed_cves"]["source_sha256"]
    cpp_rows = []
    unnormalized_mismatches = []
    hash_mismatches = []
    for path, old in baseline_rows.items():
        data = git(args.repo_dir, "show", f"{COMMIT}:{path}")
        source_sha = hashlib.sha256(data).hexdigest()
        if baseline_hashes.get(path) != source_sha or current_hashes.get(path) != source_sha:
            hash_mismatches.append(path)
        normalized_status, normalized_nodes = node_diagnostics(data, normalize=True)
        raw_status, raw_nodes = node_diagnostics(data, normalize=False)
        ast_status = parse_source(data.decode("utf-8"), "cpp").parse_status
        if normalized_status != ast_status or normalized_status != current_rows[path]["status"]:
            raise SystemExit("normalized parser replay differs from current D68 report: " + path)
        if raw_status != old["status"]:
            unnormalized_mismatches.append(path)
        old_issues = [json.loads(item) for item in old["issues"]]
        cpp_rows.append({
            "file": path,
            "source_sha256": source_sha,
            "D50_status": old["status"],
            "D50_recorded_issues": old_issues,
            "D50_issue_detail_boundary": "only kind/start_line/end_line stored; no parser node type, column, message, or AST",
            "D68_status": current_rows[path]["status"],
            "D68_recorded_issues": [json.loads(item) for item in current_rows[path]["issues"]],
            "current_normalized_node_diagnostics": normalized_nodes,
            "current_unnormalized_status": raw_status,
            "current_unnormalized_node_diagnostics": raw_nodes,
        })

    source_paths = git(args.repo_dir, "ls-tree", "-r", "--name-only", COMMIT).decode().splitlines()
    script_paths = [path for path in source_paths if path.lower().endswith((".ts", ".js", ".ets"))]
    ts_boundary = {
        "paths": script_paths,
        "D50_status": "not_run",
        "D50_reason": "Tree-sitter JavaScript/TypeScript grammars recorded unavailable in the D50 environment.",
        "D68_status": "not_run",
        "D68_reason": "Tree-sitter JavaScript/TypeScript grammars unavailable in the D68 environment.",
    }

    dispositions = {
        "interfaces/kits/napi/src/napi_init.cpp": (
            "C++ parse ERROR nodes at the NapiInit return-type region (line 26) and `_module` initializer (line 42); exact grammar/extension cause is unconfirmed.",
            "Recreate the pinned historical runtime, inspect full AST nodes, and validate the N-API translation unit with its real build flags before considering recovery.",
        ),
        "services/core/include/i_pasteboard_observer.h": (
            "ERROR node covers the UTF-prefixed descriptor string inside DECLARE_INTERFACE_DESCRIPTOR at line 30; macro expansion context is absent.",
            "Resolve the macro definition and preprocess with the component include/define set; only then assess a parser fixture.",
        ),
        "services/core/include/i_pasteboard_service.h": (
            "ERROR node covers the UTF-prefixed descriptor string inside DECLARE_INTERFACE_DESCRIPTOR at line 43; macro expansion context is absent.",
            "Resolve the macro definition and preprocess with the component include/define set; only then assess a parser fixture.",
        ),
        "services/core/include/pasteboard_service.h": (
            "MISSING semicolon nodes follow DECLARE_SYSTEM_ABILITY and DECLARE_DELAYED_SINGLETON at lines 52-53; macros may expand into declarations.",
            "Resolve both macro definitions and preprocessed class body before adding syntax normalization.",
        ),
        "services/core/src/pasteboard_storage.cpp": (
            "ERROR node at line 88 covers `std::make_shared`; raw source reads `std::make_shared PasteboardStorage(file)`.",
            "Compile this exact translation unit with its project toolchain and macro/include configuration to distinguish source syntax from parser recovery needs.",
        ),
        "services/test/unittest/src/paste_service_test.cpp": (
            "Nine MISSING semicolon nodes follow HWTEST_F invocations at lines 60, 83, 94, 105, 117, 130, 152, 175, and 198; test macro expansions are unavailable.",
            "Resolve the HWTEST_F definition and preprocess the test with its real build flags before considering a parser change.",
        ),
        "services/zidl/include/pasteboard_observer_stub.h": (
            "MISSING type_identifier inside the pointer-to-member alias at line 34; current node parent is qualified_identifier.",
            "Add an isolated grammar fixture for this valid declarator form and verify byte/line mapping before any parser normalizer change.",
        ),
        "services/zidl/include/pasteboard_service_stub.h": (
            "MISSING type_identifier inside the pointer-to-member alias at line 35; current node parent is qualified_identifier.",
            "Add an isolated grammar fixture for this valid declarator form and verify byte/line mapping before any parser normalizer change.",
        ),
        "services/zidl/src/pasteboard_observer_stub.cpp": (
            "D50 ERROR at line 46 is the `(this->*memberFunc)(...)` dispatch form; current frozen offset-preserving normalization parses it completely.",
            "No additional repair; keep the existing normalizer and rerun only if the historical runtime is restored.",
        ),
        "services/zidl/src/pasteboard_service_stub.cpp": (
            "D50 ERROR at line 58 is the `(this->*memberFunc)(...)` dispatch form; current frozen offset-preserving normalization parses it completely.",
            "No additional repair; keep the existing normalizer and rerun only if the historical runtime is restored.",
        ),
    }
    blocked_items = []
    for row in cpp_rows:
        if row["D50_status"] != "partial":
            continue
        observed, dependency = dispositions[row["file"]]
        blocked_items.append({
            "file": row["file"],
            "source_sha256": row["source_sha256"],
            "D50_status": row["D50_status"],
            "D50_recorded_issues": row["D50_recorded_issues"],
            "D68_status": row["D68_status"],
            "current_node_diagnostics": row["current_normalized_node_diagnostics"],
            "disposition": "resolved_by_existing_frozen_parser_normalizer" if row["D68_status"] == "complete" else "blocked_no_attributable_low_risk_fix",
            "observed_context": observed,
            "next_dependency": dependency,
        })
    blocked_items.append({
        "file": script_paths[0] if len(script_paths) == 1 else None,
        "D50_status": "not_run",
        "D68_status": "not_run",
        "disposition": "blocked_frontend_unavailable",
        "observed_context": "The exact source is a TypeScript declaration; both reports record JavaScript/TypeScript grammars unavailable.",
        "next_dependency": "Install and pin the TypeScript grammar/frontend, then rerun this source scope; do not count this as a C++ parse failure.",
    })

    output = {
        "task": "D67",
        "status": "blocked_manifest",
        "source": {"commit": COMMIT, "tree": TREE, "hashes_verified_for_all_cpp_units": not hash_mismatches,
                   "hash_mismatches": hash_mismatches},
        "historical_environment": baseline["environment"],
        "current_environment": current["environment"],
        "source_scope": {"declared_files": 68, "cpp_units": len(cpp_rows), "typescript_boundary_units": len(script_paths)},
        "D50_parse_counts": baseline["source_parsing"]["parsing_status"],
        "D68_parse_counts": current["source_parsing"]["parsing_status"],
        "D50_detector_analysis_reason": "detector_model_incomplete is a separate detector-coverage reason, not a parser diagnostic.",
        "historical_artifact_limitation": "D50 report records parser issue kind and line range only. The exact Python 3.10.12 runtime is not installed locally; Python 3.10.11 is installed without tree-sitter packages.",
        "unnormalized_current_runtime_ablation": {
            "result": "matches all D50 per-file statuses and kind/line issue records under the current runtime" if not unnormalized_mismatches else "mismatch",
            "mismatches": unnormalized_mismatches,
            "interpretation": "The D51 member-pointer normalization is a reproducible source-code difference explaining the two zidl stub parse-status changes in the current runtime. This does not prove the historical Python runtime had no effect."
        },
        "files": cpp_rows,
        "blocked_manifest": blocked_items,
        "typescript_boundary": ts_boundary,
        "repair_decision": {
            "new_parser_fix": "none",
            "reason": "The two member-pointer call errors are already handled by the offset-preserving normalizer in the frozen D65/D68 baseline. The remaining eight parser partials involve macro-expanded declarations/tests, unsupported declarator syntax, designated initialization, or source syntax requiring compile-context validation. D50 does not retain sufficient node details to attribute those to a narrow parser defect, and the exact historical runtime cannot be reconstructed locally.",
            "next_dependencies": [
                "Recreate Python 3.10.12 with the pinned Tree-sitter package versions for an exact historical runtime replay.",
                "Capture parser node type, column, source excerpt, and AST for the exact historical runtime.",
                "Provide project macro definitions and compile/preprocessor configuration before attempting macro-aware recovery.",
                "Validate the pasteboard_storage.cpp line 88 syntax against the component build before deciding whether it is source-invalid or context-dependent."
            ]
        }
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "files": len(cpp_rows), "hash_mismatches": hash_mismatches,
                      "unnormalized_mismatches": unnormalized_mismatches,
                      "D50": output["D50_parse_counts"], "D68": output["D68_parse_counts"]}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
