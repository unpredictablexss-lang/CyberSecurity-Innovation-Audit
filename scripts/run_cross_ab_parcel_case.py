"""Run the first controlled cross A/B Parcel length case.

This uses reviewed synthetic IPC fixtures, not a product build. A contributes
length/capacity candidates and range facts; B contributes Parcel/API boundary
semantics. The output is a combined evidence record, not a vulnerability claim.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, Sequence

PROJECT_ROOT = Path(__file__).resolve().parents[1]
import sys
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.bounds_detector import CppBoundsDetector
from src.ohscanner.detectors.cpp.integer_bounds_detector import CppIntegerBoundsDetector
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.facts import build_fact_view_v2
from src.ohscanner.fixture import snapshot_digest


def evaluate(path: Path, category: str) -> Dict[str, Any]:
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
        request_id="cross-ab-parcel:" + category,
        repository="fixture/ipc",
        commit="4" * 40,
        snapshot_sha256=snapshot_digest((unit,)),
        target_id="current-component:fixture/ipc",
        profile_id="fixture-no-build",
        provenance="fixture",
    )
    context = ScanContext(
        request=request,
        units=(unit,),
        shared_facts={"ast": {unit.path: index.to_dict()}},
    )
    ipc = IpcInterfaceDetector().detect(context, (unit,))
    bounds = CppBoundsDetector().detect(context, (unit,))
    integer = CppIntegerBoundsDetector().detect(context, (unit,))
    facts = build_fact_view_v2({unit.path: index.to_dict()})
    facts[unit.path]["ranges"] = [{
        "file": unit.path,
        "symbol": "n",
        "minimum": 0,
        "maximum": 64 if category == "fixed" else None,
        "unit": "bytes",
        "confidence": "derived_from_explicit_guard" if category == "fixed" else "unknown",
        "proof_ref": "explicit destination guard" if category == "fixed" else None,
    }]
    return {
        "category": category,
        "source": {
            "path": unit.path,
            "sha256": unit.sha256,
            "parse_status": unit.parse_status,
        },
        "a_bounds_findings": [item.__dict__ for item in bounds.findings],
        "a_integer_findings": [item.__dict__ for item in integer.findings],
        "b_ipc_findings": [item.__dict__ for item in ipc.findings],
        "facts_v2": facts,
        "combined_evidence_obligations": sorted({
            obligation.kind
            for run in (bounds, integer, ipc)
            for finding in run.findings
            for obligation in finding.evidence_obligations
        }),
        "limitations": [
            "Synthetic fixed fixture, not a product build or real-world exploit.",
            "A range fact is a bounded analysis aid, not a proof of runtime attacker control.",
            "B Parcel semantics and A length facts remain separate evidence layers; no causal security claim is made.",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", type=Path, default=PROJECT_ROOT / "tests/fixtures/ipc")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    rows = [
        evaluate(args.fixtures / "parcel_positive.cpp", "positive"),
        evaluate(args.fixtures / "parcel_fixed.cpp", "fixed"),
    ]
    report = {
        "schema_version": 1,
        "experiment_kind": "cross_a_b_parcel_length_case",
        "status": "completed_with_limitations",
        "cases": rows,
        "expected_shape": {
            "positive": "A bounds candidate + B ipc.parcel.copy-range + unbounded range fact",
            "fixed": "A bounds quiet + B parcel quiet + bounded range fact",
        },
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=lambda item: item.__dict__) + chr(10), encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
