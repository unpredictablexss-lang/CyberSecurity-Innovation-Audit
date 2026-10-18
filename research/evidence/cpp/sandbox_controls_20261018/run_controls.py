#!/usr/bin/env python3
"""Replay A-line detectors over the delivered sample30 sandbox method controls.

The copy-range controls are source-derived reduced models: the model and safe
control must stay quiet, the deliberately unsafe control must produce a bounds
candidate. The shared_ptr controls exercise local shared_ptr objects, which are
outside the class-member rule; they are recorded as not_applicable rather than
counted as misses.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Sequence


PROJECT_ROOT = Path(__file__).resolve().parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.bounds_detector import CppBoundsDetector
from src.ohscanner.detectors.cpp.integer_bounds_detector import (
    CppIntegerBoundsDetector,
)
from src.ohscanner.detectors.cpp.resource_lifetime_detector import (
    CppResourceLifetimeDetector,
)
from src.ohscanner.detectors.cpp.shared_ptr_race_detector import SharedPtrRaceDetector
from src.ohscanner.detectors.cpp.unsafe_memory_call_detector import (
    CppUnsafeMemoryCallDetector,
)
from src.ohscanner.fixture import snapshot_digest


CONTROL_DIR = (
    PROJECT_ROOT
    / "research"
    / "deliveries"
    / "a-line-sample30"
    / "20261018"
    / "evidence"
    / "sandbox"
    / "method_controls"
)

COPY_RANGE_EXPECTATIONS = {
    "copy_range_model.cpp": 0,
    "copy_range_safe_control.cpp": 0,
    "copy_range_unsafe_control.cpp": 1,
}

LOCAL_ONLY_CONTROLS = (
    "shared_ptr_tsan_unsafe_control.cpp",
    "shared_ptr_tsan_atomic_control.cpp",
)


def _source(path: Path) -> SourceUnit:
    text = path.read_text(encoding="utf-8")
    return SourceUnit(
        path=f"research/deliveries/a-line-sample30/20261018/evidence/sandbox/method_controls/{path.name}",
        language="cpp",
        text=text,
        sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        parse_status="complete",
    )


def _context(units: Sequence[SourceUnit]) -> ScanContext:
    ordered = tuple(sorted(units, key=lambda item: item.path))
    return ScanContext(
        request=ScanRequest(
            request_id="a-line:sandbox-controls-20261018",
            repository="openharmony-sample30/method-controls",
            commit="0" * 40,
            snapshot_sha256=snapshot_digest(ordered),
            target_id="current-component:openharmony-sample30/method-controls",
            profile_id="sandbox-method-control-v1",
            provenance="fixture",
        ),
        units=ordered,
    )


def _run(path: Path, detectors: Sequence[Any]) -> Dict[str, Any]:
    unit = _source(path)
    context = _context((unit,))
    runs = []
    for detector in detectors:
        run = detector.detect(context, (unit,))
        runs.append({
            "detector": run.detector_id,
            "version": run.version,
            "status": run.status,
            "findings": [
                {
                    "rule_id": item.rule_id,
                    "file": item.file,
                    "line": item.line,
                    "column": item.column,
                    "symbol": item.symbol,
                    "message": item.message,
                }
                for item in run.findings
            ],
            "limitations": list(run.limitations),
        })
    return {
        "file": path.name,
        "sha256": unit.sha256,
        "byte_length": len(unit.text.encode("utf-8")),
        "runs": runs,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-dir", type=Path, default=CONTROL_DIR)
    parser.add_argument("--out-dir", type=Path, default=Path(__file__).resolve().parent)
    args = parser.parse_args(argv)

    bounds = CppBoundsDetector()
    detectors = (
        bounds,
        CppIntegerBoundsDetector(),
        CppResourceLifetimeDetector(),
        CppUnsafeMemoryCallDetector(),
        SharedPtrRaceDetector(),
    )

    copy_range: List[Dict[str, Any]] = []
    failures: List[str] = []
    for name, expected_minimum in sorted(COPY_RANGE_EXPECTATIONS.items()):
        result = _run(args.control_dir / name, detectors)
        bounds_run = next(
            item for item in result["runs"] if item["detector"] == bounds.detector_id
        )
        count = len(bounds_run["findings"])
        result["bounds_candidates"] = count
        result["expected_minimum"] = expected_minimum
        result["result"] = (
            "passed"
            if (count >= 1) == (expected_minimum >= 1)
            else "failed"
        )
        if result["result"] == "failed":
            failures.append(
                f"{name}: bounds candidates={count}, expected minimum={expected_minimum}"
            )
        copy_range.append(result)

    shared_ptr: List[Dict[str, Any]] = []
    for name in LOCAL_ONLY_CONTROLS:
        result = _run(args.control_dir / name, (SharedPtrRaceDetector(),))
        result["result"] = "not_applicable"
        result["reason"] = (
            "local shared_ptr objects are outside the class-member race rule; "
            "the dynamic TSan control validates the method, not this detector"
        )
        shared_ptr.append(result)

    summary = {
        "schema_version": 1,
        "experiment_kind": "a_line_sandbox_method_control_static_replay",
        "status": "passed" if not failures else "failed",
        "detectors": {
            "bounds": bounds.version,
        },
        "copy_range_controls": copy_range,
        "shared_ptr_controls": shared_ptr,
        "failures": failures,
        "limitations": [
            "Reduced models validate the method only; they are not product builds or product PoCs.",
            "Candidate presence/absence is a narrow control result, not Precision/Recall.",
            "No confirmed vulnerability or dedicated PoC is claimed.",
        ],
    }
    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print("status=" + summary["status"])
    for item in copy_range:
        print(f"{item['file']} bounds={item['bounds_candidates']} {item['result']}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
