"""Replay exact BuiltinsDataView API parent/fixed sources against the registered Ark rule.

Run from the project root:
  python research/deliveries/c-line/dataview_api_width_proof_replay_20261020.py --git-dir <local-ark-object-store>

This is a local research replay. It does not test generated Ark IR or product behavior.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from src.parser.ast import parse_source


REPOSITORY = "openharmony/arkcompiler_ets_runtime"
PATH = "ecmascript/builtins/builtins_dataview.cpp"
PINS = (
    {
        "role": "parent",
        "commit": "d62f6de64daa7e11a7936a6153748a7c5fae9e41",
        "tree": "a26f18bc7b1cd97fb926ae61b3655ddbf2caf8d1",
        "blob": "e6bac984354292405ae62f7728170d7be5e3760e",
        "sha256": "bc01e0f8b8a2a5ab30d1478587b45a14aa8130d3d53dfb32b9513ff4d73bc38c",
    },
    {
        "role": "fixed",
        "commit": "48fcec3686e45175f95b4600b579026a65149966",
        "tree": "6ff7f405071d29fc3ecf9bac1abd9d59a485909f",
        "blob": "a2376e822e995333b2400520ca5b882de9578b5e",
        "sha256": "39b1ed79451980ad85e1176805deaf6c6315bca09d7676ea5c63f5ff1c4bd65b",
    },
)
DEPENDENCIES = (
    ("ecmascript/js_dataview.cpp", "5057a103a88096b5db0e39be0feca2864a2ff8eb",
     "3782d04ee5c44504bf453b3b45f96d7431ff902fb575257c425c707890b83243"),
    ("ecmascript/base/number_helper.cpp", "a648bf6cf36715d57c6466f0ab4bfdc00bdc8f35",
     "94db5ecc8ff7ea79d656950abacd9c24756ccf6aa0e3b2b895d7dc9961dbc91f"),
)


def git(git_dir: str, *args: str, binary: bool = False):
    result = subprocess.run(
        ["git", "--git-dir=" + git_dir, *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return result.stdout if binary else result.stdout.decode("utf-8").strip()


def replay(git_dir: str, pin: dict[str, str], include_dependencies: bool) -> dict[str, object]:
    tree = git(git_dir, "rev-parse", pin["commit"] + "^{tree}")
    blob = git(git_dir, "rev-parse", pin["commit"] + ":" + PATH)
    raw = git(git_dir, "show", pin["commit"] + ":" + PATH, binary=True)
    source_sha256 = hashlib.sha256(raw).hexdigest()
    if (tree, blob, source_sha256) != (pin["tree"], pin["blob"], pin["sha256"]):
        raise SystemExit(f"source identity mismatch for {pin['role']}")

    text = raw.decode("utf-8")
    ast = parse_source(text, "cpp")
    unit = SourceUnit(
        PATH, "cpp", text, source_sha256, ast.parse_status,
        tuple(json.dumps(item, sort_keys=True) for item in ast.parse_issues),
    )
    units = [unit]
    asts = {PATH: ast.to_dict()}
    blobs = {PATH: blob}
    if include_dependencies:
        for dependency_path, expected_blob, expected_sha in DEPENDENCIES:
            dep_blob = git(git_dir, "rev-parse", pin["commit"] + ":" + dependency_path)
            dep_raw = git(git_dir, "show", pin["commit"] + ":" + dependency_path, binary=True)
            dep_sha = hashlib.sha256(dep_raw).hexdigest()
            if (dep_blob, dep_sha) != (expected_blob, expected_sha):
                raise SystemExit(f"dependency identity mismatch for {pin['role']}: {dependency_path}")
            dep_text = dep_raw.decode("utf-8")
            dep_ast = parse_source(dep_text, "cpp")
            dep_unit = SourceUnit(dependency_path, "cpp", dep_text, dep_sha, dep_ast.parse_status,
                                  tuple(json.dumps(item, sort_keys=True) for item in dep_ast.parse_issues))
            units.append(dep_unit)
            asts[dependency_path] = dep_ast.to_dict()
            blobs[dependency_path] = dep_blob
    units.sort(key=lambda item: item.path)
    request = ScanRequest(
        "ib8bca-api-" + pin["role"], REPOSITORY, pin["commit"],
        snapshot_digest(tuple(units)), "current-component:" + REPOSITORY,
        "light-ast", "git_object",
    )
    context = ScanContext(request, tuple(units), {
        "ast": asts,
        "source_blob_oid": blobs,
    })
    registry = DetectorRegistry()
    registry.register(ArkRuntimeTypeSafetyDetector())
    reports, coverage = run_all_with_coverage(context, registry)
    report = reports[0]
    sidecar = coverage["detectors"][report.tool]
    return {
        **pin,
        "dependencies_supplied": include_dependencies,
        "parse_status": ast.parse_status,
        "parse_issue_count": len(ast.parse_issues),
        "detector_status": report.status,
        "diagnostics": [
            {"rule_id": item.rule_id, "line": item.line, "source_sha256": item.source_sha256}
            for item in report.diagnostics
        ],
        "coverage_status": sidecar["status"],
        "applicable_files": sidecar["applicable_files"],
        "analyzed_files": sidecar["analyzed_files"],
        "partially_inspected_files": sidecar["partially_inspected_files"],
        "unexamined": sidecar["unexamined"],
        "limitations": list(report.limitations),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--git-dir", required=True, help="local Ark Runtime Git object store")
    args = parser.parse_args()
    result = {
        "repository": REPOSITORY,
        "path": PATH,
        "method": "exact Git blobs -> complete AST -> git_object/light-ast ScanContext -> registered Ark Runtime detector via run_all_with_coverage",
        "results": [replay(args.git_dir, pin, supplied)
                    for pin in PINS for supplied in (False, True)],
        "limitations": [
            "Candidate/zero-finding output is not a vulnerability/safety verdict.",
            "Partial detector model coverage remains unknown.",
            "No generated IR, runtime, product, or exploitability validation is performed.",
        ],
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
