"""Measure the current six-family IPC fixture coverage census."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest


def context_for(path: Path):
    text = path.read_text(encoding="utf-8")
    index = parse_source(text, language="cpp")
    unit = SourceUnit(
        path="tests/fixtures/ipc/" + path.name,
        language="cpp",
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        parse_status=index.parse_status,
    )
    request = ScanRequest(
        request_id="ipc-family-census",
        repository="fixture/ipc",
        commit="6" * 40,
        snapshot_sha256=snapshot_digest((unit,)),
        target_id="current-component:fixture/ipc",
        profile_id="fixture-no-build",
        provenance="fixture",
    )
    return ScanContext(request, (unit,), {"ast": {unit.path: index.to_dict()}}), unit


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=PROJECT_ROOT / "tests/fixtures/ipc")
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument("--recovery-manifest", type=Path)
    args = parser.parse_args()
    recovery = json.loads(args.recovery_manifest.read_text(encoding="utf-8")) if args.recovery_manifest else None
    manifest = json.loads((args.fixtures / "manifest.json").read_text(encoding="utf-8"))
    rows = []
    counts = defaultdict(Counter)
    for item in manifest:
        context, unit = context_for(args.fixtures / item["file"])
        run = IpcInterfaceDetector().detect(context, (unit,))
        rules = {finding.rule_id for finding in run.findings}
        expected = item.get("expected_rule")
        matched = expected in rules if expected else not rules
        counts[item["family"]][item["variant"]] += 1
        counts[item["family"]]["matched" if matched else "mismatch"] += 1
        rows.append({
            "sample_id": item["sample_id"],
            "family": item["family"],
            "variant": item["variant"],
            "expected_rule": expected,
            "observed_rules": sorted(rules),
            "matched": matched,
            "detector_status": run.status,
            "source_sha256": unit.sha256,
        })
    summary = {
        "schema_version": 1,
        "experiment_kind": "ipc_six_family_coverage_census",
        "status": "completed_with_limitations",
        "families": {family: dict(counter) for family, counter in sorted(counts.items())},
        "totals": {
            "samples": len(rows),
            "matched": sum(row["matched"] for row in rows),
            "mismatch": sum(not row["matched"] for row in rows),
        },
        "rows": rows,
        "external_input_recovery": {"canonical_content_digest": recovery["canonical_content_digest"], "counts": recovery["counts"]} if recovery else None,
        "limitations": [
            "Synthetic design controls only; not product entry reachability or vulnerability truth.",
            "A matched expected rule is rule coverage, not a validated vulnerability.",
            ("Recovered work/ipc-20261017 source is bound by " + recovery["canonical_content_digest"] + "; PR-ref recovery shows every selected source blob already present at current HEAD.") if recovery else "No external IPC recovery manifest was supplied.",
        ],
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + chr(10), encoding="utf-8")
    lines = ["# IPC six-family coverage census", "", f"Samples: {summary['totals']['samples']}; matched: {summary['totals']['matched']}; mismatch: {summary['totals']['mismatch']}.", "", "| Family | Positive | Fixed | Safe | Other | Matched | Mismatch |", "|---|---:|---:|---:|---:|---:|---:|"]
    for family, counter in sorted(counts.items()):
        other = sum(counter.values()) - counter["positive"] - counter["fixed"] - counter["safe"] - counter["matched"] - counter["mismatch"]
        lines.append(f"| {family} | {counter['positive']} | {counter['fixed']} | {counter['safe']} | {other} | {counter['matched']} | {counter['mismatch']} |")
    lines.extend(["", "Synthetic coverage only; no product vulnerability claim.", ""])
    (args.out_dir / "summary.md").write_text(chr(10).join(lines), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
