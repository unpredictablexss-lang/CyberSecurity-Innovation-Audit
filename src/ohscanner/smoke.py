"""M0 smoke entry point: exercise two FIRST-PARTY MOCK detectors only."""

import json
from pathlib import Path

from src.benchmark.tool_result import render_markdown
from .fixture import load_fixture, verify_fixture_unchanged
from .mocks import MockCppDetector, MockInterfaceDetector
from .runner import DetectorRegistry, run_all


def run_mock_smoke(fixture_root: Path, json_out: Path, md_out: Path):
    if json_out.resolve() == md_out.resolve():
        raise ValueError("JSON and Markdown report paths must differ")
    context = load_fixture(fixture_root)
    registry = DetectorRegistry()
    registry.register(MockCppDetector())
    registry.register(MockInterfaceDetector())
    runs = run_all(context, registry)
    verify_fixture_unchanged(fixture_root, context)
    report = {
        "schema_version": 1,
        "experiment_kind": "m0_synthetic_contract_smoke",
        "repository": context.request.repository,
        "commit": context.request.commit,
        "snapshot_sha256": context.request.snapshot_sha256,
        "provenance": context.request.provenance,
        "validated_vulnerability": 0,
        "runs": [run.to_dict() for run in runs],
        "interpretation": "Only synthetic contract markers were scanned; not a real OpenHarmony scan."
    }
    json_out.parent.mkdir(parents=True, exist_ok=True)
    md_out.parent.mkdir(parents=True, exist_ok=True)
    json_out.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    md = ["# OHScanner M0 synthetic contract smoke test", "",
          "> Mock detector output only. No real security validation.", "",
          f"- Snapshot SHA-256: `{context.request.snapshot_sha256}`", "",
          "- Validated vulnerabilities: **0**", ""]
    for run in runs:
        md.extend([render_markdown(run), ""])
    md_out.write_text("\n".join(md), encoding="utf-8")
    return report
