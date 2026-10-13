"""Build teammate-A evidence sidecars deterministically under ignored outputs.

This records curated metadata and baseline status cells. It does not execute
scanners, copy target source, or commit generated experiment outputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
OUTPUT_DIR = ROOT / "outputs/reports/static_baselines"
EVIDENCE_PATH = OUTPUT_DIR / "evidence_units.json"
BASELINE_PATH = OUTPUT_DIR / "baseline_status.json"

INTERFACE_BASELINE = {
    "branch": "feat/workbench-integration",
    "head": "fe85edd6431b09e01131608fa649286264ca2c2e",
    "contract_path": "src/ohscanner/contracts.py",
    "contract_sha256": "b50fce29acdb4a22e79abdc0b96039d6823bc0cdb2a281c7d40cde0cfc06c408",
}

TOOLS = ["own_text", "own_ast", "semgrep", "semgrep_oh", "cppcheck", "clang_sa", "codeql", "joern"]

PARSING_DETAIL_TO_STATUS = {
    "complete": "complete",
    "complete_unresolved_symbol": "partial",
    "partial_cast_problem": "partial",
    "partial_macro_context": "partial",
    "partial_missing_includes": "partial",
    "partial_parser_problems": "partial",
    "failed": "failed",
    "not_applicable_no_source_files": "not_run",
    "not_applicable_no_translation_unit": "not_run",
    "not_run": "not_run",
}

SAMPLES = {
    "c_utils-singleton-uaf-2026-01": {
        "stem": "c_utils_singleton_uaf",
        "repository": "openharmony/commonlibrary_c_utils",
        "repo_url": "https://github.com/openharmony/commonlibrary_c_utils",
        "root_cause_group": "lifetime_uaf",
        "weakness": "CWE-416",
        "file": "base/include/singleton.h",
        "pair_analysis_unit_id": "c_utils-singleton-uaf-2026-01:pair:base/include/singleton.h:DelayedSingleton",
        "symbols": ["GetInstance", "DestroyInstance"],
        "vulnerable": {
            "commit": "bdfafdaafddb01ab7ae13354ce2ada9555d7935c",
            "sha256": "ce04ace5a2ad702d3f56e30be347dc9583c808dcf5aac80ee761bd70e05f1ad4",
            "blob": "0e0c91010e39558202ab1c7f628c618fd7a09d23",
            "tree": "b3ec65d247c4ca1ff07318fa72c0daa368128563",
            "bytes": 6010,
            "lines": 212,
        },
        "fixed": {
            "commit": "9a3f281120307ec7dcce17fae882dcc4e6a6f4d7",
            "sha256": "9ed18694defc088c7bfe69327f6e4668d6c23d72a4f3c5516ad4635e9e511606",
            "blob": "fb65b4d89ff9c60c54bc6a8e106b06935f23f633",
            "tree": "69fbea434f22e2174a4dd79dff6ad25833e0ea49",
            "bytes": 6043,
            "lines": 214,
        },
    },
    "kernel_liteos_a-getgroups-oob-2025-03": {
        "stem": "kernel_liteos_a_getgroups_oob",
        "repository": "openharmony/kernel_liteos_a",
        "repo_url": "https://github.com/openharmony/kernel_liteos_a",
        "root_cause_group": "concurrency_race",
        "weakness": "CWE-125",
        "file": "syscall/process_syscall.c",
        "pair_analysis_unit_id": "kernel_liteos_a-getgroups-oob-2025-03:pair:syscall/process_syscall.c:GetGroups",
        "symbols": ["GetGroups"],
        "vulnerable": {
            "commit": "6ac8e246b0efd57a28ea05b6e6973ae0602fe032",
            "sha256": "c00871f4989136366672035383dfa03464f32cb9f675f3f5c7d4cb9ddaf1ccc7",
            "blob": "48c5f81791cfe3f8682a5c2f8ad5d1fddfa6e041",
            "tree": "d871d7772afffa7a084485d2e8570d1bb7634ea3",
            "bytes": 33053,
            "lines": 1414,
        },
        "fixed": {
            "commit": "940a5a8c2cd1ced84d435933dbcdbb1a7fbf3000",
            "sha256": "36a5c34f9fd5c38e4f0011e4ae207e8b22c74ecffccdce8700470f53e1ace10d",
            "blob": "59d914f784bdfb37781b8e7c142fe251527d80f9",
            "tree": "220e1d9eb5278e1f5a6804f7c42b3ee7f269297c",
            "bytes": 33133,
            "lines": 1416,
        },
    },
    "communication_dsoftbus_null_deref_001": {
        "stem": "communication_dsoftbus_null_deref",
        "repository": "openharmony/communication_dsoftbus",
        "repo_url": "https://github.com/openharmony/communication_dsoftbus",
        "root_cause_group": "null_deref",
        "weakness": "CWE-476",
        "file": "core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp",
        "pair_analysis_unit_id": "communication_dsoftbus_null_deref_001:pair:core/bus_center/ipc/standard/src/bus_center_client_proxy.cpp:BusCenterClientProxy",
        "symbols": [
            "ClinetOnNodeOnlineStateChanged",
            "ClinetOnNodeBasicInfoChanged",
            "ClientOnNodeStatusChanged",
            "ClinetOnLocalNetworkIdChanged",
            "ClinetNotifyDeviceNotTrusted",
        ],
        "vulnerable": {
            "commit": "258662cd9840b55a31546a72d91027f6368cea84",
            "sha256": "5453bd68645a7708f0d9ef9c214451a4735a256b5223729f6808ab34095125a6",
            "blob": "a82b71fb5520b02278a4af695bbe918d14c1048e",
            "tree": "366a4ced9400653c9628c0b677e4ae657c0e7bd8",
            "bytes": 8502,
            "lines": 226,
        },
        "fixed": {
            "commit": "192f3e11d74beeaa3d879333471deb8a24a7e1c5",
            "sha256": "5a093d91efc624147d40bf3f4dbbe3ab7ab6d724b17978298e9d5c30d9e5eb81",
            "blob": "13ddbe93a7f617784dec0f3761e09f66b5c3217c",
            "tree": "1d58ba0ef706a6f69dd372bd496c8058810882aa",
            "bytes": 9387,
            "lines": 246,
        },
    },
    "arkcompiler_ets_runtime-jsarray-sort-oob-2025-02": {
        "stem": "arkcompiler_ets_runtime_jsarray_sort_oob",
        "repository": "openharmony/arkcompiler_ets_runtime",
        "repo_url": "https://github.com/openharmony/arkcompiler_ets_runtime",
        "root_cause_group": "oob_write",
        "weakness": "CWE-787",
        "file": "ecmascript/js_array.cpp",
        "pair_analysis_unit_id": "arkcompiler_ets_runtime-jsarray-sort-oob-2025-02:pair:ecmascript/js_array.cpp:SortElementsByObject",
        "symbols": ["SortElementsByObject"],
        "vulnerable": {
            "commit": "aeee3fd12c03193545edea4b8e0fdfa3d9a03d11",
            "sha256": "b7f28be2f63850ba1cb57a35d518930986855784d2081124e555f2a57d673e9b",
            "blob": "2c58914ad27b6b3c5f570dbd2fe0ed02d1d9e471",
            "tree": "0eea26c9eb6846f4d19926be83092c06f0d98692",
            "bytes": 31896,
            "lines": 732,
        },
        "fixed": {
            "commit": "1b23531531e768398682582969c2a9f17e72cafe",
            "sha256": "f6325075773451b9c9a314c6fec0c0177331786f5c9e6ce3069974eb4c79b0f6",
            "blob": "58266855967e3dc4af97721d3a2fc5417cb887b6",
            "tree": "52f27683e2f6e1ba8272aee7d5202c73059e10b4",
            "bytes": 32924,
            "lines": 754,
        },
    },
}

STATUS = {
    "c_utils-singleton-uaf-2026-01": {
        "vulnerable": {
            "own_text": ("completed", "complete", "miss", 0, ""),
            "own_ast": ("completed", "complete", "miss", 0, ""),
            "semgrep": ("completed", "complete", "miss", 0, ""),
            "semgrep_oh": ("completed", "complete", "possible_hit", 1, ""),
            "cppcheck": ("completed", "complete_unresolved_symbol", "unknown", 0, "Diagnostic symbol unresolved; region overlap cannot be decided."),
            "clang_sa": ("blocked", "not_applicable_no_translation_unit", "not_applicable", 0, "Affected-file snapshot cannot form a C++ translation unit because required headers are absent."),
            "codeql": ("failed", "not_applicable_no_source_files", "not_applicable", 0, "No-build extraction reports zero source files and one header for this header-only analysis unit."),
            "joern": ("failed", "partial_cast_problem", "unknown", 0, "CASTProblem/partial parsing prevents complete affected-file coverage."),
        },
        "fixed": {
            "own_text": ("completed", "complete", "miss", 0, ""),
            "own_ast": ("completed", "complete", "miss", 0, ""),
            "semgrep": ("completed", "complete", "miss", 0, ""),
            "semgrep_oh": ("completed", "complete", "miss", 0, ""),
            "cppcheck": ("completed", "complete_unresolved_symbol", "unknown", 0, "Diagnostic symbol unresolved; region overlap cannot be decided."),
            "clang_sa": ("blocked", "not_applicable_no_translation_unit", "not_applicable", 0, "Affected-file snapshot cannot form a C++ translation unit because required headers are absent."),
            "codeql": ("failed", "not_applicable_no_source_files", "not_applicable", 0, "No-build extraction reports zero source files and one header for this header-only analysis unit."),
            "joern": ("failed", "partial_cast_problem", "unknown", 0, "CASTProblem/partial parsing prevents complete affected-file coverage."),
        },
    },
    "kernel_liteos_a-getgroups-oob-2025-03": {
        revision: {
            "own_text": ("completed", "complete", "miss", 0, ""),
            "own_ast": ("completed", "partial_macro_context", "unknown", 0, "Tree-sitter reports a macro-context parse problem; zero diagnostics are not a miss."),
            "semgrep": ("completed", "partial_macro_context", "unknown", 0, "Semgrep reports 41 diagnostics plus PartialParsing; region coverage remains incomplete."),
            "semgrep_oh": ("completed", "partial_macro_context", "unknown", 0, "Pinned AST is partial near the macro context."),
            "cppcheck": ("completed", "partial_macro_context", "unknown", 0, "Pinned AST is partial near the macro context."),
            "clang_sa": ("blocked", "not_applicable_no_translation_unit", "not_applicable", 0, "Affected-file snapshot cannot form a translation unit because required headers/build context are absent."),
            "codeql": ("completed", "partial_missing_includes", "unknown", 0, "SARIF telemetry reports missing includes; successful exit is not complete extraction."),
            "joern": ("failed", "partial_parser_problems", "unknown", 0, "CPG parser problems prevent complete affected-file coverage."),
        }
        for revision in ("vulnerable", "fixed")
    },
    "communication_dsoftbus_null_deref_001": {
        "vulnerable": {
            "own_text": ("completed", "complete", "miss", 0, ""),
            "own_ast": ("completed", "complete", "miss", 0, ""),
            "semgrep": ("completed", "complete", "miss", 0, ""),
            "semgrep_oh": ("completed", "complete", "possible_hit", 5, ""),
            "cppcheck": ("completed", "complete", "miss", 0, ""),
            "clang_sa": ("blocked", "not_applicable_no_translation_unit", "not_applicable", 0, "Affected-file snapshot cannot form a translation unit because required headers are absent."),
            "codeql": ("completed", "partial_missing_includes", "unknown", 0, "SARIF telemetry reports missing includes; successful exit is not complete extraction."),
            "joern": ("completed", "complete", "possible_hit", 5, ""),
        },
        "fixed": {
            "own_text": ("completed", "complete", "miss", 0, ""),
            "own_ast": ("completed", "complete", "miss", 0, ""),
            "semgrep": ("completed", "complete", "miss", 0, ""),
            "semgrep_oh": ("completed", "complete", "miss", 0, ""),
            "cppcheck": ("completed", "complete", "miss", 0, ""),
            "clang_sa": ("blocked", "not_applicable_no_translation_unit", "not_applicable", 0, "Affected-file snapshot cannot form a translation unit because required headers are absent."),
            "codeql": ("completed", "partial_missing_includes", "unknown", 0, "SARIF telemetry reports missing includes; successful exit is not complete extraction."),
            "joern": ("completed", "complete", "miss", 0, ""),
        },
    },
    "arkcompiler_ets_runtime-jsarray-sort-oob-2025-02": {
        revision: {
            "own_text": ("completed", "complete", "miss", 0, ""),
            "own_ast": ("completed", "complete", "miss", 0, ""),
            "semgrep": ("completed", "complete", "miss", 0, ""),
            "semgrep_oh": ("completed", "complete", "miss", 0, ""),
            "cppcheck": ("completed", "complete", "possible_hit", 1, ""),
            "clang_sa": ("blocked", "not_applicable_no_translation_unit", "not_applicable", 0, "Affected-file snapshot cannot form a translation unit because required headers/build context are absent."),
            "codeql": ("completed", "partial_missing_includes", "unknown", 0, "SARIF telemetry reports missing includes; successful exit is not complete extraction."),
            "joern": ("completed", "complete", "miss", 0, ""),
        }
        for revision in ("vulnerable", "fixed")
    },
}


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_sha(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def tree_manifest_sha(path: Path) -> str:
    lines = []
    for item in sorted(p for p in path.rglob("*") if p.is_file()):
        lines.append(f"{file_sha(item)}  {item.relative_to(path).as_posix()}\n")
    return sha256_bytes("".join(lines).encode("utf-8"))


def combined_manifest_sha(paths: list[Path]) -> str:
    lines = [f"{file_sha(path)}  {path.relative_to(ROOT).as_posix()}\n" for path in sorted(paths)]
    return sha256_bytes("".join(lines).encode("utf-8"))


def tool_spec(tool: str) -> dict:
    if tool == "own_text":
        return {
            "name": tool,
            "version": "text-v1",
            "configuration": {
                "config_id": "own-text-dangerous-api-v1",
                "config_artifact": "src/core/scanner.py",
                "config_sha256": file_sha(ROOT / "src/core/scanner.py"),
                "config_sha256_status": "verified_sha256",
            },
        }
    if tool == "own_ast":
        return {
            "name": tool,
            "version": "tree-sitter exact baseline version not retained in checked-in summary",
            "configuration": {
                "config_id": "own-ast-v1",
                "config_artifact": ["src/parser/ast.py", "src/core/ast_scanner.py"],
                "config_sha256": combined_manifest_sha([ROOT / "src/parser/ast.py", ROOT / "src/core/ast_scanner.py"]),
                "config_sha256_status": "verified_sha256",
            },
        }
    if tool == "semgrep":
        return {
            "name": tool,
            "version": "Semgrep CE 1.179.0",
            "configuration": {
                "config_id": "semgrep-vendor-raptor-dae50da6",
                "config_artifact": "rules/cpp/vendor/raptor",
                "config_sha256": tree_manifest_sha(ROOT / "rules/cpp/vendor/raptor"),
                "config_sha256_status": "verified_sha256",
                "upstream_commit": "dae50da6e6e629750f1daec73a01ef9206a372ab",
                "license": "MIT; LICENSE retained under rules/cpp/vendor/raptor",
            },
        }
    if tool == "semgrep_oh":
        return {
            "name": tool,
            "version": "Semgrep CE 1.179.0",
            "configuration": {
                "config_id": "semgrep-oh-two-rule-research-profile",
                "config_artifact": ["rules/cpp/oh_shared_ptr_uaf.yaml", "rules/cpp/oh_nothrow_null_deref.yaml"],
                "config_sha256": combined_manifest_sha([ROOT / "rules/cpp/oh_shared_ptr_uaf.yaml", ROOT / "rules/cpp/oh_nothrow_null_deref.yaml"]),
                "config_sha256_status": "verified_sha256",
                "license": "Project-authored research rules; no third-party rule text copied",
            },
        }
    if tool == "cppcheck":
        command = "cppcheck --xml --xml-version=2 --enable=warning,style,performance,portability --inconclusive <affected-files>"
        return {
            "name": tool,
            "version": "Cppcheck 2.7",
            "configuration": {
                "config_id": "cppcheck-warning-style-performance-portability-inconclusive",
                "config_artifact": "command line recorded in docs/testing/static_experiments_2026-10-08.md",
                "config_sha256": sha256_bytes(command.encode("utf-8")),
                "config_sha256_status": "verified_sha256",
                "command": command,
            },
        }
    if tool == "clang_sa":
        return {
            "name": tool,
            "version": "Clang 14.0.0",
            "configuration": {
                "config_id": "clang-sa-affected-file-snapshot",
                "config_artifact": "src/baseline/clang_analyzer.py",
                "config_sha256": file_sha(ROOT / "src/baseline/clang_analyzer.py"),
                "config_sha256_status": "verified_sha256",
            },
        }
    if tool == "codeql":
        return {
            "name": tool,
            "version": "CodeQL 2.27.1; cpp-queries 1.9.0",
            "configuration": {
                "config_id": "codeql-cpp-security-and-quality-qls-1.9.0-no-build",
                "config_artifact": "external cpp-queries 1.9.0 codeql-suites/cpp-security-and-quality.qls; not committed",
                "config_sha256": None,
                "config_sha256_status": "not_retained_in_checked_in_replay_summary",
            },
        }
    if tool == "joern":
        return {
            "name": tool,
            "version": "Joern 4.0.649",
            "configuration": {
                "config_id": "joern-nothrow-structural-guard-query",
                "config_artifact": "scripts/joern_nothrow_guard.sc",
                "config_sha256": file_sha(ROOT / "scripts/joern_nothrow_guard.sc"),
                "config_sha256_status": "verified_sha256",
                "query_scope": "nothrow null-guard structural heuristic only; not an oob_write or lifetime_uaf query",
            },
        }
    raise ValueError(tool)


def source_artifact(sample_id: str, revision: str) -> dict:
    sample = SAMPLES[sample_id]
    item = sample[revision]
    return {
        "repository_path": sample["file"],
        "canonical_url": (
            f"https://raw.githubusercontent.com/{sample['repository']}/{item['commit']}/{sample['file']}"
        ),
        "retrieval": "raw bytes at exact commit; source bytes are not committed",
        "git_commit": item["commit"],
        "source_file_sha256": item["sha256"],
        "git_blob_sha1": item["blob"],
        "git_tree_sha1": item["tree"],
        "bytes": item["bytes"],
        "lines": item["lines"],
    }


def snapshot_digest(unit_identities: list[dict]) -> str:
    manifest = [
        (unit["path"], unit["language"], unit["sha256"])
        for unit in unit_identities
    ]
    raw = json.dumps(manifest, separators=(",", ":"), ensure_ascii=False)
    return sha256_bytes(raw.encode("utf-8"))


def scan_context_identity(
    sample_id: str,
    revision: str,
    control_role: str,
    analysis_unit_id: str,
    scope: dict,
    source: dict,
    repository: str,
) -> dict:
    unit_identity = {
        "path": source["repository_path"],
        "language": "cpp",
        "sha256": source["source_file_sha256"],
        "parse_status": "not_run",
        "parse_issues": [],
    }
    return {
        "request": {
            "request_id": f"historical:{analysis_unit_id}",
            "repository": repository,
            "commit": source["git_commit"],
            "snapshot_sha256": snapshot_digest([unit_identity]),
            "target_id": f"current-component:{repository}",
            "profile_id": "light-ast",
            "provenance": "git_object",
        },
        # SourceUnit identity projection. Target text is intentionally omitted;
        # the exact source artifact hash binds it without committing third-party source.
        "units": [unit_identity],
        "shared_facts": {
            "sample_id": sample_id,
            "revision": revision,
            "control_role": control_role,
            "analysis_unit_id": analysis_unit_id,
            "scope": scope,
            "source_artifact": source,
        },
    }


def run_binding(scan_context: dict, scope: dict, tool: dict, run_id: str | None) -> dict:
    request = scan_context["request"]
    return {
        "run_id": run_id,
        "tool": tool["name"],
        "tool_version": tool["version"],
        "target_id": request["target_id"],
        "commit": request["commit"],
        "scope_files": scope["scope_files"],
        "scope_loc": scope["scope_loc"],
    }


def binding_digest(record: dict) -> str:
    fields = {key: value for key, value in record.items() if key != "binding_sha256"}
    raw = json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return sha256_bytes(raw.encode("utf-8"))


def parsing_coverage(detail: str, scope_files: int) -> dict:
    if type(scope_files) is not int or scope_files < 1:
        raise ValueError("scope_files must be a positive integer")
    try:
        status = PARSING_DETAIL_TO_STATUS[detail]
    except KeyError as error:
        raise ValueError(f"unsupported parsing detail: {detail}") from error
    counts = {
        "files_complete": 0,
        "files_partial": 0,
        "files_failed": 0,
        "files_not_run": 0,
    }
    counts[f"files_{status}"] = scope_files
    return {"status": status, "status_detail": detail, **counts}


def baseline_unit(sample_id: str, revision: str, tool: str) -> dict:
    sample = SAMPLES[sample_id]
    source = sample[revision]
    execution_status, parsing_status, result_status, evidence_count, reason = STATUS[sample_id][revision][tool]
    run_id = (
        f"{sample_id}:{revision}:{'text' if tool == 'own_text' else 'ast'}"
        if tool in {"own_text", "own_ast"}
        else f"{sample['stem']}.{revision}.{tool}"
    )
    analysis_unit_id = f"{sample['pair_analysis_unit_id']}:{revision}"
    scope_files = 1
    limitations = [
        "Affected-file snapshot only; no full product build or runtime validation.",
        "possible_hit is region/rule overlap only; miss is not a false negative and empty output is not proof of safety.",
    ]
    if reason:
        limitations.append(reason)
    record = {
        "schema_version": 1,
        "record_type": "evidence_unit",
        "evidence_level": "reconstructed_metadata",
        "reconstruction_run_key": run_id,
        "run_id_origin": "reconstructed_key_not_verified_native_execution_id",
        "evidence_unit_id": f"{analysis_unit_id}:{tool}:{run_id}",
        "sample_id": sample_id,
        "repository": sample["repository"],
        "exact_commit": source["commit"],
        "revision": revision,
        "control_role": revision,
        "scope": {
            "analysis_unit_id": analysis_unit_id,
            "scope_kind": "historical_affected_region",
            "files": [sample["file"]],
            "symbols": sample["symbols"],
            "scope_files": scope_files,
            "scope_loc": source["lines"],
        },
        "source_artifact": source_artifact(sample_id, revision),
        "source_file_sha256": source["sha256"],
        "git_blob_sha1": source["blob"],
        "git_tree_sha1": source["tree"],
        "tool": tool_spec(tool),
        "run_id": run_id,
        "execution_status": execution_status,
        "parsing_coverage": parsing_coverage(parsing_status, scope_files),
        "result_status": result_status,
        "result_evidence_count": evidence_count,
        "limitations": limitations,
        "provenance": {
            "source": "Existing local baseline transcribed from docs/testing/static_experiments_2026-10-08.md and PROGRAM_STATUS.md.",
            "source_license": "Apache-2.0 repository source; retain upstream headers/notices.",
            "third_party_source_committed": False,
            "rule_provenance": (
                "rules/cpp/vendor/raptor is an unmodified MIT mirror pinned to dae50da6; "
                "semgrep_oh rules are project-authored research patterns."
            ),
        },
        "artifact_bindings": {
            "normalized_result_reference": {
                "logical_path": f"outputs/reports/static_baselines/{sample['stem']}.{revision}.{tool}.json",
                "sha256": None,
                "sha256_status": "raw_output_not_committed_and_hash_not_retained_in_checked_in_summary",
            },
            "native_output_reference": {
                "logical_path": f"outputs/reports/static_baselines/{sample['stem']}.{revision}.{tool}.native",
                "sha256": None,
                "sha256_status": "raw_output_not_committed_and_hash_not_retained_in_checked_in_summary",
            },
        },
    }
    record["tool"]["configuration"]["hash_provenance"] = "current_checkout_configuration_not_verified_historical_runtime"
    record["scan_context_identity"] = scan_context_identity(
        sample_id, revision, revision, analysis_unit_id, record["scope"],
        record["source_artifact"], sample["repository"],
    )
    record["run_binding"] = run_binding(
        record["scan_context_identity"], record["scope"], record["tool"], run_id
    )
    if result_status == "not_applicable":
        record["not_applicable_reason"] = reason
    record["binding_sha256"] = binding_digest(record)
    return record


SAFE_CONTROLS = {
    "c_utils-singleton-uaf-2026-01": {
        "analysis_unit_id": "c_utils-singleton-uaf-2026-01:fixed:safe:Singleton_GetInstance",
        "symbols": ["Singleton<T>::GetInstance"],
        "line_ranges": [[197, 206]],
        "shape": "Eager singleton accessor returning a static reference; no shared_ptr publication race in this analysis unit.",
    },
    "arkcompiler_ets_runtime-jsarray-sort-oob-2025-02": {
        "analysis_unit_id": "arkcompiler_ets_runtime-jsarray-sort-oob-2025-02:fixed:safe:CheckStableArray_guards",
        "symbols": ["JSArray::CheckStableArrayAndSet", "JSArray::CheckStableArrayAndGet"],
        "line_ranges": [[673, 693]],
        "shape": "Stable-array and element-length guards around direct ElementAccessor access.",
    },
}


def safe_unit(sample_id: str, tool: str) -> dict:
    sample = SAMPLES[sample_id]
    control = SAFE_CONTROLS[sample_id]
    revision = "fixed"
    source = sample[revision]
    run_id = None
    scope_files = 1
    record = {
        "schema_version": 1,
        "record_type": "evidence_unit",
        "evidence_unit_id": f"{control['analysis_unit_id']}:{tool}:not_run",
        "sample_id": sample_id,
        "repository": sample["repository"],
        "exact_commit": source["commit"],
        "revision": revision,
        "control_role": "safe",
        "scope": {
            "analysis_unit_id": control["analysis_unit_id"],
            "scope_kind": "safe_shape_control",
            "files": [sample["file"]],
            "symbols": control["symbols"],
            "line_ranges": control["line_ranges"],
            "scope_files": scope_files,
            "scope_loc": source["lines"],
        },
        "source_artifact": source_artifact(sample_id, revision),
        "source_file_sha256": source["sha256"],
        "git_blob_sha1": source["blob"],
        "git_tree_sha1": source["tree"],
        "tool": tool_spec(tool),
        "run_id": run_id,
        "execution_status": "not_run",
        "parsing_coverage": parsing_coverage("not_run", scope_files),
        "result_status": "unknown",
        "result_evidence_count": 0,
        "limitations": [
            "Safe control was defined but no tool run was executed in this round.",
            "The control is shape-scoped and is not proof of universal safety.",
            "Separate from the vulnerable/fixed pair; never merge its result with the fixed pair.",
        ],
        "provenance": {
            "source": "Safe control definition from the pinned fixed source artifact.",
            "source_license": "Apache-2.0 repository source; retain upstream headers/notices.",
            "third_party_source_committed": False,
            "rule_provenance": "Configuration identity is recorded for future runs; no run output exists.",
        },
        "artifact_bindings": {
            "normalized_result_reference": {"logical_path": None, "sha256": None, "sha256_status": "not_run"},
            "native_output_reference": {"logical_path": None, "sha256": None, "sha256_status": "not_run"},
        },
    }
    record["scan_context_identity"] = scan_context_identity(
        sample_id, revision, "safe", control["analysis_unit_id"], record["scope"],
        record["source_artifact"], sample["repository"],
    )
    record["run_binding"] = run_binding(
        record["scan_context_identity"], record["scope"], record["tool"], run_id
    )
    record["binding_sha256"] = binding_digest(record)
    return record


def build() -> tuple[str, str]:
    units = [
        baseline_unit(sample_id, revision, tool)
        for sample_id in SAMPLES
        for revision in ("vulnerable", "fixed")
        for tool in TOOLS
    ]
    units.extend(safe_unit(sample_id, tool) for sample_id in SAFE_CONTROLS for tool in TOOLS)
    evidence = {
        "schema_version": 1,
        "package_id": "teammate-a-native-corpus-and-cpp-baseline-2026-10-09",
        "interface_baseline": INTERFACE_BASELINE,
        "interpretation": (
            "Evidence bindings and raw benchmark states only. possible_hit is candidate overlap; "
            "miss is not a false negative; unknown is missing/failed/incomplete; not_applicable requires "
            "an explicit incompatible-analysis-unit reason. No vulnerability verdict or Precision/Recall is computed."
        ),
        "units": units,
    }
    evidence_text = json.dumps(evidence, separators=(",", ":"), ensure_ascii=False) + "\n"

    baseline_units = [unit for unit in units if unit["control_role"] in {"vulnerable", "fixed"}]
    counts = Counter(unit["result_status"] for unit in baseline_units)
    by_sample = defaultdict(Counter)
    by_tool = defaultdict(Counter)
    for unit in baseline_units:
        by_sample[unit["sample_id"]][unit["result_status"]] += 1
        by_tool[unit["tool"]["name"]][unit["result_status"]] += 1
    baseline = {
        "schema_version": 1,
        "source_of_truth": "outputs/reports/static_baselines/evidence_units.json",
        "interface_baseline": INTERFACE_BASELINE,
        "scope": "4 historical samples x 2 revisions x 8 tools = 64 cells",
        "counts": {key: counts.get(key, 0) for key in ("possible_hit", "miss", "unknown", "not_applicable")},
        "count_semantics": "Counts are cells, not vulnerabilities or TP/FP/FN.",
        "by_sample": {key: dict(value) for key, value in sorted(by_sample.items())},
        "by_tool": {key: dict(value) for key, value in sorted(by_tool.items())},
        "cells": [
            {
                "evidence_unit_id": unit["evidence_unit_id"],
                "sample_id": unit["sample_id"],
                "revision": unit["revision"],
                "tool": unit["tool"]["name"],
                "run_id": unit["run_id"],
                "request_id": unit["scan_context_identity"]["request"]["request_id"],
                "target_id": unit["scan_context_identity"]["request"]["target_id"],
                "commit": unit["scan_context_identity"]["request"]["commit"],
                "snapshot_sha256": unit["scan_context_identity"]["request"]["snapshot_sha256"],
                "profile_id": unit["scan_context_identity"]["request"]["profile_id"],
                "provenance": unit["scan_context_identity"]["request"]["provenance"],
                "execution_status": unit["execution_status"],
                "parsing_coverage": unit["parsing_coverage"]["status"],
                "result_status": unit["result_status"],
                "result_evidence_count": unit["result_evidence_count"],
                "binding_sha256": unit["binding_sha256"],
            }
            for unit in baseline_units
        ],
    }
    return evidence_text, json.dumps(baseline, indent=2, ensure_ascii=False) + "\n"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="write deterministic sidecars")
    mode.add_argument(
        "--check",
        action="store_true",
        help="check that existing deterministic sidecars match the builder",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    evidence_text, baseline_text = build()
    if args.write:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
        EVIDENCE_PATH.write_text(evidence_text, encoding="utf-8")
        BASELINE_PATH.write_text(baseline_text, encoding="utf-8")
        print(f"[OK] wrote {EVIDENCE_PATH.relative_to(ROOT)} and {BASELINE_PATH.relative_to(ROOT)}")
        return
    mismatches = []
    for path, expected in ((EVIDENCE_PATH, evidence_text), (BASELINE_PATH, baseline_text)):
        if not path.exists() or path.read_text(encoding="utf-8") != expected:
            mismatches.append(str(path.relative_to(ROOT)))
    if mismatches:
        raise SystemExit("deterministic sidecar mismatch: " + ", ".join(mismatches))
    print("[OK] deterministic evidence sidecars match")


if __name__ == "__main__":
    main()
