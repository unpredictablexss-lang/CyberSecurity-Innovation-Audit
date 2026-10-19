#!/usr/bin/env python3
"""C13 bounded real-source replay and fail-closed object inventory.

This experiment deliberately does not alter the shared scanner. It verifies
local pinned Git objects and invokes the production ``ohscan-run`` entry point
with the historical model selected only for this process. Missing/mismatched
objects are errors; no synthetic source is substituted for a real pair.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[4]
RECORD = {
    "commit": "4c56210",
    "path": "research/deliveries/c-line/OHScanner_G盘源码漏洞审查记录_20261018.md",
    "blob": "dbedea677c8dc70c1b0066c7bc52df27bcff06ea",
    "bytes": 29553,
}
CASE_ID = "IBS5YG"
RULE_ID = "ark.runtime.typedarray-store-type-origin"
TARGET_PATH = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
PARENT = {
    "commit": "2ea501258ab4155826b64f01b499b43d1911e0e2",
    "tree": "579712c1ebbb703d17cea422b1572023bed5d8a4",
    "blob": "054451b1be4f39254d56a1683cc9d1c1b5e55018",
    "sha256": "847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422",
}
FIXED = {
    "commit": "919e4fbb011f610427e788889083fa8e28d2f951",
    "tree": "82af11ced4297818410ccf61906b703d25b69165",
    "blob": "95f54f2875f401afe3167c62f8c1e7799782be8c",
    "sha256": "8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e",
}
# The source-audit table has nine C13 cases. Only IBS5YG has a complete
# source-bound parent/fixed pair in this slice; the rest remain explicit
# obligations rather than inferred passes.
OTHER_CASES = (
    "CVE-2025-24304", "I7KZJ7", "IC7B8Q", "I7E0FM", "IAO7GO",
    "I7W51D", "IB8BCA", "IAO7E8",
)


class C13ObjectError(RuntimeError):
    """Raised when a pinned object is absent or does not match its manifest."""


@dataclass(frozen=True)
class GitObject:
    kind: str
    oid: str
    size: int | None = None


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    # A partial clone may otherwise lazy-fetch on missing objects. C13 is
    # strictly local and must fail closed instead.
    env["GIT_NO_LAZY_FETCH"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def git(repo: Path, *args: str, text: bool = True) -> str | bytes:
    command = ["git", "-C", str(repo), *args]
    proc = subprocess.run(command, env=_git_env(), capture_output=True, text=text)
    if proc.returncode:
        detail = proc.stderr if text else proc.stderr.decode("utf-8", "replace")
        raise C13ObjectError(f"git {' '.join(args)} failed: {detail.strip()}")
    return proc.stdout


def verify_object(repo: Path, oid: str, expected_type: str, *, size: int | None = None) -> GitObject:
    kind = git(repo, "cat-file", "-t", oid).strip()
    if kind != expected_type:
        raise C13ObjectError(f"object_type_mismatch:{oid}:{kind}!={expected_type}")
    raw_size = int(git(repo, "cat-file", "-s", oid).strip())
    if size is not None and raw_size != size:
        raise C13ObjectError(f"object_size_mismatch:{oid}:{raw_size}!={size}")
    return GitObject(kind, oid, raw_size)


def verify_record(repo: Path) -> dict[str, Any]:
    # The source-audit blob belongs to OHScanner, not the Ark target store.
    verify_object(PROJECT_ROOT, RECORD["blob"], "blob", size=RECORD["bytes"])
    return dict(RECORD, status="verified")


def verify_source(repo: Path, revision: dict[str, str], path: str = TARGET_PATH) -> dict[str, Any]:
    commit = revision["commit"]
    verify_object(repo, commit, "commit")
    tree = git(repo, "rev-parse", f"{commit}^{{tree}}").strip()
    if tree != revision["tree"]:
        raise C13ObjectError(f"tree_mismatch:{commit}:{tree}!={revision['tree']}")
    row = git(repo, "ls-tree", commit, "--", path).strip()
    parts = row.split()
    if len(parts) < 4 or parts[1] != "blob" or parts[2] != revision["blob"]:
        raise C13ObjectError(f"blob_mismatch:{commit}:{path}:{row}")
    raw = git(repo, "cat-file", "blob", revision["blob"], text=False)
    digest = hashlib.sha256(raw).hexdigest()
    if digest != revision["sha256"]:
        raise C13ObjectError(f"source_sha256_mismatch:{commit}:{path}")
    return {
        "commit": commit,
        "tree": tree,
        "path": path,
        "blob": revision["blob"],
        "sha256": digest,
        "bytes": len(raw),
        "status": "verified",
    }


def inventory(repo: Path) -> dict[str, Any]:
    record = verify_record(repo)
    pair = {
        "case_id": CASE_ID,
        "rule_id": RULE_ID,
        "repository": "openharmony/arkcompiler_ets_runtime",
        "scope": [TARGET_PATH],
        "profile": "light-ast",
        "parent": verify_source(repo, PARENT),
        "fixed": verify_source(repo, FIXED),
    }
    return {
        "schema_version": 1,
        "source_audit": record,
        "cases": [pair],
        "unresolved_cases": [
            {"case_id": item, "status": "source_object_or_profile_obligation_open"}
            for item in OTHER_CASES
        ],
        "fail_closed": True,
    }


def _filter_root_diagnostics(report: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        item
        for run in report.get("detector_runs", ())
        for item in run.get("diagnostics", ())
        if item.get("rule_id") == RULE_ID
    ]


def run_cli(repo: Path, out_dir: Path, revision: dict[str, str], label: str) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_out = out_dir / f"{CASE_ID.lower()}-{label}.json"
    md_out = out_dir / f"{CASE_ID.lower()}-{label}.md"
    root = PROJECT_ROOT
    experiment_dir = Path(__file__).resolve().parent
    env = _git_env()
    env["PYTHONPATH"] = os.pathsep.join((str(experiment_dir), str(root)))
    cmd = [
        sys.executable, "-m", "src.cli", "ohscan-run",
        "--repo-dir", str(repo), "--repository", "openharmony/arkcompiler_ets_runtime",
        "--commit", revision["commit"], "--include", TARGET_PATH,
        "--detector", "ohscanner.ark.runtime.type_safety",
        "--json-out", str(json_out), "--md-out", str(md_out),
    ]
    proc = subprocess.run(cmd, cwd=root, env=env, capture_output=True, text=True)
    if proc.returncode:
        raise C13ObjectError(f"production_cli_failed:{label}:{proc.stderr.strip()}")
    report = json.loads(json_out.read_text(encoding="utf-8"))
    return {
        "label": label,
        "argv": cmd,
        "returncode": proc.returncode,
        "report": str(json_out),
        "same_root_diagnostics": _filter_root_diagnostics(report),
        "diagnostic_count": report.get("diagnostic_count"),
        "run_status": report.get("detector_runs", [{}])[0].get("status"),
        "task_status": report.get("status"),
    }


def replay(repo: Path, out_dir: Path) -> dict[str, Any]:
    manifest = inventory(repo)
    parent = run_cli(repo, out_dir, PARENT, "parent")
    fixed = run_cli(repo, out_dir, FIXED, "fixed")
    result = {
        "schema_version": 1,
        "case_id": CASE_ID,
        "manifest": manifest,
        "production_cli": {"parent": parent, "fixed": fixed},
        "expected_shape": {"parent": "candidate", "fixed": "no_same_root_candidate"},
        "observed_shape": {
            "parent_same_root_count": len(parent["same_root_diagnostics"]),
            "fixed_same_root_count": len(fixed["same_root_diagnostics"]),
        },
        "status": "blocked_partial_unknown"
        if parent["run_status"] == "blocked" or fixed["run_status"] == "blocked"
        else "replayed",
        "interpretation": (
            "The pair is source-bound and the production CLI reports are retained. "
            "If either side is blocked/partial, a zero count is not a safe result."
        ),
    }
    (out_dir / "c13-replay-result.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-dir", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).parent / "reports")
    parser.add_argument("--inventory-only", action="store_true")
    args = parser.parse_args()
    payload = inventory(args.repo_dir) if args.inventory_only else replay(args.repo_dir, args.out_dir)
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

