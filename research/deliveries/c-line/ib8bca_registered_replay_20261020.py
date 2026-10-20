"""Replay the exact IB8BCA parent/fixed files against the registered Ark rule.

Run from the project root:
  python research/deliveries/c-line/ib8bca_registered_replay_20261020.py --git-dir <local-ark-object-store>

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
PATH = "ecmascript/compiler/builtins/builtins_dataview_stub_builder.cpp"
PINS = (
    {
        "role": "parent",
        "commit": "d62f6de64daa7e11a7936a6153748a7c5fae9e41",
        "tree": "a26f18bc7b1cd97fb926ae61b3655ddbf2caf8d1",
        "blob": "aedb6d26681535371d1e9ed90b697b923b8100e6",
        "sha256": "bd55a638db7292305dd7b564c5767657e105a48f064c66809934f5e3e6a5f548",
    },
    {
        "role": "fixed",
        "commit": "48fcec3686e45175f95b4600b579026a65149966",
        "tree": "6ff7f405071d29fc3ecf9bac1abd9d59a485909f",
        "blob": "dce9388e8b7e33c87aec33ac4d067fe40370561b",
        "sha256": "89fd548588f59a5f0756868957ff011609264b7d10437a8636c3f3262da1d386",
    },
)


def git(git_dir: str, *args: str, binary: bool = False):
    result = subprocess.run(
        ["git", "--git-dir=" + git_dir, *args], check=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return result.stdout if binary else result.stdout.decode("utf-8").strip()


def replay(git_dir: str, pin: dict[str, str]) -> dict[str, object]:
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
    request = ScanRequest(
        "ib8bca-" + pin["role"], REPOSITORY, pin["commit"],
        snapshot_digest((unit,)), "current-component:" + REPOSITORY,
        "light-ast", "git_object",
    )
    context = ScanContext(request, (unit,), {
        "ast": {PATH: ast.to_dict()},
        "source_blob_oid": {PATH: blob},
    })
    registry = DetectorRegistry()
    registry.register(ArkRuntimeTypeSafetyDetector())
    reports, coverage = run_all_with_coverage(context, registry)
    report = reports[0]
    sidecar = coverage["detectors"][report.tool]
    return {
        **pin,
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
        "results": [replay(args.git_dir, pin) for pin in PINS],
        "limitations": [
            "Candidate/zero-finding output is not a vulnerability/safety verdict.",
            "Partial detector model coverage remains unknown.",
            "No generated IR, runtime, product, or exploitability validation is performed.",
        ],
    }
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
