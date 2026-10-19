"""Direct, bounded replay for D19's cJSON compare-cost candidate.

This does not invoke the parser or production CLI. Call with the exact vulnerable
source path from the source ledger; parse_status stays partial by design. The
official develop commit is an experimental patch control, never a fixed version.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO_ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.resource_lifetime_detector import (
    CppResourceLifetimeDetector,
    RULE_RECURSIVE_COMPARE_COST,
    RULE_VERSION,
)
from src.ohscanner.fixture import snapshot_digest


EXPECTED_VULNERABLE_SHA256 = "427c72055ae68467b451599f36da074351a5ca53f6e103cd30064e32cf0fffbb"
EXPERIMENTAL_COMMIT = "bd307ec3b5f1c0555976c4b0118621e485367aa2"
FIXTURE_DIR = REPO_ROOT / "tests/detectors/fixtures/cpp_resource_lifetime"


def replay(path: str, text: str, *, parse_status: str, commit: str) -> dict[str, object]:
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    unit = SourceUnit(path=path, language="c", text=text, sha256=digest, parse_status=parse_status)
    repository = "openharmony/third_party_cjson"
    context = ScanContext(
        request=ScanRequest(
            request_id="d19:" + path,
            repository=repository,
            commit=commit,
            snapshot_sha256=snapshot_digest((unit,)),
            target_id="current-component:" + repository,
            profile_id="light-ast",
            provenance="git_object",
        ),
        units=(unit,),
    )
    started = time.perf_counter()
    result = CppResourceLifetimeDetector().detect(context, (unit,))
    elapsed = time.perf_counter() - started
    findings = [
        {
            "line": item.line,
            "column": item.column,
            "rule_id": item.rule_id,
            "symbol": item.symbol,
            "source_sha256": item.source_sha256,
        }
        for item in result.findings
        if item.rule_id == RULE_RECURSIVE_COMPARE_COST
    ]
    return {
        "input": path,
        "commit_label": commit,
        "parse_status": parse_status,
        "run_status": result.status,
        "rule_version": RULE_VERSION,
        "source_bytes": len(text.encode("utf-8")),
        "source_sha256": digest,
        "elapsed_seconds": elapsed,
        "findings": findings,
        "scope_note": "direct detector replay only; parser and CLI coverage are not evaluated",
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--vulnerable-source", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()

    vulnerable_text = args.vulnerable_source.read_text(encoding="utf-8")
    vulnerable_hash = hashlib.sha256(vulnerable_text.encode("utf-8")).hexdigest()
    if vulnerable_hash != EXPECTED_VULNERABLE_SHA256:
        raise SystemExit(f"vulnerable source hash mismatch: {vulnerable_hash}")

    develop_text = subprocess.check_output(
        ["git", "show", f"{EXPERIMENTAL_COMMIT}:cJSON.c"],
        cwd=REPO_ROOT,
        text=True,
    )
    cases = [
        replay(
            "third_party/cjson/cJSON.c",
            vulnerable_text,
            parse_status="partial",
            commit="105eaddbf0d0110b07d16bdefc81ffc796e1444a",
        ),
        replay(
            "renamed/cJSON.c",
            re.sub(r"\bcJSON_Compare\b", "compare_json_nodes", vulnerable_text),
            parse_status="partial",
            commit="105eaddbf0d0110b07d16bdefc81ffc796e1444a",
        ),
        replay(
            "experimental/d17-develop-bd307ec/cJSON.c",
            develop_text,
            parse_status="partial",
            commit=EXPERIMENTAL_COMMIT,
        ),
    ]
    for filename in (
        "safe_recursive_compare_indexed_lookup.c",
        "safe_recursive_compare_cost.c",
    ):
        text = (FIXTURE_DIR / filename).read_text(encoding="utf-8")
        cases.append(
            replay(
                "tests/detectors/fixtures/cpp_resource_lifetime/" + filename,
                text,
                parse_status="complete",
                commit="2" * 40,
            )
        )
    payload = {
        "schema_version": 1,
        "experiment": "D19 cJSON recursive compare root precision",
        "classification": "no_change",
        "fixed_control": False,
        "experimental_patch_commit": EXPERIMENTAL_COMMIT,
        "cases": cases,
    }
    rendered = json.dumps(payload, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")


if __name__ == "__main__":
    main()
