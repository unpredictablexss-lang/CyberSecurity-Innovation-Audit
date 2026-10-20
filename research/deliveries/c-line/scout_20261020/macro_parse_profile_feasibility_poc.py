"""Non-production probe for pinned C1 macro parsing feasibility.

Reads Git objects only. It does not compile or execute target code and does not
modify the source tree. Requires this repository's Tree-sitter and cpp_macros.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
from src.parser.ast import parse_source
from src.ohscanner.detectors.interface.cpp_macros import macro_catalog, expand_with_catalog

COMMIT = "a65a2853ccae13da167d9aa4720ab8b11ec16656"
TARGET = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
HEADERS = (
    "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.h",
    "ecmascript/compiler/stub_builder.h",
    "ecmascript/compiler/circuit_builder.h",
)
TOOLS = ("clang", "clang++", "clang-cl", "g++", "gcc", "cl", "cpp")


def git_blob(git_dir, revision, path):
    return subprocess.check_output(
        ["git", "--git-dir=" + str(git_dir), "show", revision + ":" + path],
        timeout=30,
    )


def blob_oid(data):
    return hashlib.sha1(b"blob " + str(len(data)).encode("ascii") + b"\0" + data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--git-dir", required=True)
    args = parser.parse_args()
    paths = (TARGET,) + HEADERS
    sources = {path: git_blob(args.git_dir, COMMIT, path) for path in paths}
    catalog = macro_catalog(sources)

    full = expand_with_catalog(sources[TARGET], catalog)
    control = (
        b"void f() {\n  if (true) {\n    return;\n  } IR_ELSE {\n"
        b"    return;\n  }\n}\n"
    )
    expanded = expand_with_catalog(control, catalog)
    control_result = {
        "raw_parse_status": parse_source(control.decode(), "cpp").parse_status,
        "expanded_parse_status": parse_source(expanded.source.decode(), "cpp").parse_status,
        "fatal": list(expanded.fatal),
        "refused": list(expanded.refused),
        "expansions": list(expanded.expansions),
        "source_line_round_trip": {"expanded_line": 4, "original_line": expanded.original_line(4)},
    }

    refusal_controls = {}
    probes = {
        "IR_IF": b"void f() { IR_IF (true) { return; } }\n",
        "BRANCH": b"void f() { BRANCH(true, yes, no)\n}\n",
        "BUILTIN_COMPILER_TYPED_ARRAY_TYPES": (
            b"void f(int t) { switch(t) { BUILTIN_COMPILER_TYPED_ARRAY_TYPES("
            b"BUILTIN_COMPILER_TYPED_ARRAY_LABEL) default: break; } }\n"
        ),
    }
    for name, source in probes.items():
        result = expand_with_catalog(source, catalog)
        refusal_controls[name] = {
            "applied_any": result.applied,
            "fatal": list(result.fatal),
            "refused": list(result.refused),
            "expansion_count": len(result.expansions),
            "fully_resolved": not result.fatal and not result.refused,
        }

    output = {
        "schema_version": 1,
        "experiment": "pinned_c1_macro_parse_feasibility_nonproduction",
        "commit": COMMIT,
        "target": TARGET,
        "toolchain_on_path": {tool: shutil.which(tool) for tool in TOOLS},
        "source_bindings": {
            path: {"git_blob": blob_oid(data), "sha256": hashlib.sha256(data).hexdigest()}
            for path, data in sources.items()
        },
        "macro_catalog_count": len(catalog),
        "full_target_expansion": {
            "applied_any": full.applied,
            "fatal": list(full.fatal),
            "refused": list(full.refused),
            "expansion_count": len(full.expansions),
            "fully_resolved": not full.fatal and not full.refused,
        },
        "ir_else_control": control_result,
        "macro_refusal_controls": refusal_controls,
        "limitations": [
            "This probe uses the existing bounded token expander, not a C/C++ preprocessor.",
            "It does not establish a build configuration or parse completeness for the target TU.",
        ],
    }
    print(json.dumps(output, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
