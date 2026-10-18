#!/usr/bin/env python3
"""Reproduce the bounded Filter/Map owner-attribution evidence."""
from __future__ import annotations

import hashlib
import importlib.metadata
import json
import shutil
import subprocess
import sys
from pathlib import Path

DELIVERY = Path(__file__).resolve().parent
SCANNER = DELIVERY.parents[3]
sys.path.insert(0, str(SCANNER))

from src.parser.ast import parse_source  # noqa: E402
import tree_sitter_cpp  # noqa: E402
from tree_sitter import Language, Parser  # noqa: E402

COMMIT = "a65a2853ccae13da167d9aa4720ab8b11ec16656"
TREE = "8781f036a3e7e04d8e0b34970d5f623b42875016"
TARGET = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
BUILDER_HEADER = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.h"
SIGNATURE_MACROS = "ecmascript/compiler/builtins/builtins_call_signature_list.h"
TARGET_BLOB = "68fb3b0adc4f9062889a861be51b7be90362e37a"
TARGET_SHA256 = "76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c"
OWNER = "BuiltinsTypedArrayStubBuilder"
METHODS = {"Filter", "Map"}


def git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True,
        capture_output=True, text=True,
    ).stdout.strip()


def fixed_qualified_name(node, source: bytes) -> str | None:
    """Retain the qualified-id instead of descending to its final identifier."""
    declarator = node.child_by_field_name("declarator")
    if declarator is None:
        return None
    while declarator.child_by_field_name("declarator") is not None:
        declarator = declarator.child_by_field_name("declarator")
    if declarator.type == "qualified_identifier":
        return source[declarator.start_byte:declarator.end_byte].decode()
    return None


def fixed_method_owners(text: str) -> dict[str, str]:
    source = text.encode()
    parser = Parser(Language(tree_sitter_cpp.language()))
    root = parser.parse(source).root_node
    stack = [root]
    found = {}
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            qualified = fixed_qualified_name(node, source)
            if qualified:
                method = qualified.rsplit("::", 1)[-1]
                owner = qualified.rsplit("::", 1)[0].rsplit("::", 1)[-1]
                if method in METHODS:
                    found[method] = owner
        stack.extend(reversed(node.children))
    return found


def check(repo: Path) -> dict:
    assert git(repo, "rev-parse", "HEAD") == COMMIT
    assert git(repo, "rev-parse", "HEAD^{tree}") == TREE
    assert git(repo, "ls-tree", COMMIT, TARGET).split()[2] == TARGET_BLOB
    source = git(repo, "show", f"{COMMIT}:{TARGET}")
    raw = subprocess.run(
        ["git", "-C", str(repo), "show", f"{COMMIT}:{TARGET}"],
        check=True, capture_output=True,
    ).stdout
    assert hashlib.sha256(raw).hexdigest() == TARGET_SHA256

    provenance = json.loads((DELIVERY / "provenance.json").read_text())
    parser_sha256 = hashlib.sha256((SCANNER / "src/parser/ast.py").read_bytes()).hexdigest()
    assert parser_sha256 == provenance["analysis_environment"]["scanner_parser_source_sha256"]
    facts_sha256 = hashlib.sha256((SCANNER / "src/ohscanner/facts.py").read_bytes()).hexdigest()
    assert facts_sha256 == provenance["analysis_environment"]["scanner_facts_source_sha256"]
    dependency_checks = []
    for item in provenance["same_repository_dependencies"]:
        dependency_checks.append((repo, COMMIT, item))
    for item in provenance["external_repository_dependencies"]:
        dependency_repo = repo.parent / "runtime_core"
        dependency_checks.append((dependency_repo, item["commit"], item))
    for dependency_repo, dependency_commit, item in dependency_checks:
        dependency_path = item["path"]
        dependency_raw = subprocess.run(
            ["git", "-C", str(dependency_repo), "show", f"{dependency_commit}:{dependency_path}"],
            check=True, capture_output=True,
        ).stdout
        dependency_blob = git(dependency_repo, "rev-parse", f"{dependency_commit}:{dependency_path}")
        assert dependency_blob == item["blob"], (dependency_path, dependency_blob)
        assert hashlib.sha256(dependency_raw).hexdigest() == item["sha256"], dependency_path

    indexed = parse_source(source, "cpp")
    builder_header = subprocess.run(
        ["git", "-C", str(repo), "show", f"{COMMIT}:{BUILDER_HEADER}"],
        check=True, capture_output=True, text=True,
    ).stdout
    signature_macros = subprocess.run(
        ["git", "-C", str(repo), "show", f"{COMMIT}:{SIGNATURE_MACROS}"],
        check=True, capture_output=True, text=True,
    ).stdout
    header_parse = parse_source(builder_header, "cpp")
    macro_list_parse = parse_source(signature_macros, "cpp")
    observed = {f.name: f.start_line for f in indexed.functions if f.name in METHODS}
    assert observed == {"Filter": 1436, "Map": 2662}, observed
    assert indexed.parse_status == "partial", indexed.parse_status

    fixed = fixed_method_owners(source)
    assert fixed == {"Filter": OWNER, "Map": OWNER}, fixed
    indexed_methods = {f.name: f for f in indexed.functions if f.name in METHODS}
    production_owners = {name: item.owner for name, item in indexed_methods.items()}
    assert production_owners == {"Filter": OWNER, "Map": OWNER}, production_owners

    fixed_control = (DELIVERY / "controls/fixed_owner.cpp").read_text()
    fixed_control_owners = fixed_method_owners(fixed_control)
    assert fixed_control_owners == {"Filter": "FixedTypedArrayBuilder", "Map": "FixedTypedArrayBuilder"}

    safe = (DELIVERY / "controls/safe_unrelated_owner.cpp").read_text()
    safe_owners = fixed_method_owners(safe)
    assert safe_owners == {"Filter": "UnrelatedBuilder", "Map": "UnrelatedBuilder"}
    assert all(owner != OWNER for owner in safe_owners.values())

    oh_root = repo.parent.parent
    build_tools = {name: shutil.which(name) for name in ("gn", "ninja", "clang++")}

    return {
        "status": "bounded_reproduction_passed",
        "commit": COMMIT,
        "commit_parent": git(repo, "show", "-s", "--format=%P", COMMIT),
        "tree": TREE,
        "repository_remote": {
            "name": "gitcode",
            "url": git(repo, "remote", "get-url", "gitcode"),
        },
        "target_blob": TARGET_BLOB,
        "target_sha256": TARGET_SHA256,
        "dependency_blob_and_sha256_checks": len(dependency_checks),
        "frontend_parse_status": indexed.parse_status,
        "frontend_parse_issues": indexed.parse_issues,
        "declaration_header_parse_status": header_parse.parse_status,
        "method_macro_list_parse_status": macro_list_parse.parse_status,
        "macro_expansion_performed": False,
        "scanner_commit": git(SCANNER, "rev-parse", "HEAD"),
        "scanner_parser_source_sha256": parser_sha256,
        "scanner_facts_source_sha256": facts_sha256,
        "parser_packages": {
            "tree-sitter": importlib.metadata.version("tree-sitter"),
            "tree-sitter-cpp": importlib.metadata.version("tree-sitter-cpp"),
        },
        "frontend_method_names_and_lines": observed,
        "pre_fix_parser_owner_attribution": "missing (method names only)",
        "corrected_owner_attribution": fixed,
        "production_parser_owner_attribution": production_owners,
        "production_parser_qualified_names": {
            name: item.qualified_name for name, item in indexed_methods.items()
        },
        "namespace_context_in_recovered_functions": "not retained by the partial Tree-sitter tree",
        "fixed_version_control": fixed_control_owners,
        "safe_unrelated_control": safe_owners,
        "whole_file_safe": "not assessed",
        "compile_database_or_preprocessed_tu": "unavailable in pinned checkout",
        "build_environment": {
            "openharmony_out_directory_present": (oh_root / "out").exists(),
            "openharmony_prebuilts_directory_present": (oh_root / "prebuilts").exists(),
            "gn_ninja_clang_on_path": build_tools,
            "note": "System clang++ availability does not establish the OpenHarmony target toolchain or compile flags.",
        },
    }


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: reproduce.py /path/to/openharmony/arkcompiler/ets_runtime")
    result = check(Path(sys.argv[1]).resolve())
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
