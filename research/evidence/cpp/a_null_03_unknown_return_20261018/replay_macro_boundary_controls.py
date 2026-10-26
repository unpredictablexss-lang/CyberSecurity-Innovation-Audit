from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.null_dereference_detector import NullDereferenceDetector
from src.ohscanner.fixture import snapshot_digest


DETECTOR_PATH = ROOT / "src/ohscanner/detectors/cpp/null_dereference_detector.py"
CONTROL_MANIFEST = ROOT / "research/tests/a_null_02_controls/control_manifest.json"
BOUNDARY_FIXTURES = ROOT / "tests/detectors/fixtures/cpp_null_boundary"
BEFORE_SHA256 = "1caef00fcf159e66caf3e6a2ce0fb682f30cb68da7ac140f8fb0b0186e407d1f"
AFTER_SHA256 = "8976cdabe7f54ca3ba63277eb140dcc6da873e63365aa368ccc1339a9e5796be"
BASE_COMMIT = "4593a7c9b6977eb81172d01b46cc59daf46f5d45"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_before_detector(current_source: str):
    before_source = current_source.replace(
        '''        if (\n            "*" in body\n            or "->" in body\n            or re.search(r"\\[[^\\]\\n]*\\]", body)\n            or re.search(r"\\b(?:DEREFERENCE|DEREF)\\b", match.group(1))\n        ):''',
        '''        if "*" in body or re.search(r"\\b(?:DEREFERENCE|DEREF)\\b", match.group(1)):''',
    ).replace(
        'if not line.strip() or line.lstrip().startswith("#"):',
        'if line.lstrip().startswith("#"):',
    )
    before_hash = sha256(before_source.encode("utf-8"))
    if before_hash != BEFORE_SHA256:
        raise ValueError(f"pre-change detector reconstruction mismatch: {before_hash}")

    module_name = "null_dereference_pre_macro_fix"
    spec = importlib.util.spec_from_loader(module_name, loader=None)
    if spec is None:
        raise RuntimeError("could not create pre-change module spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    exec(compile(before_source, str(DETECTOR_PATH) + " [pre-change]", "exec"), module.__dict__)
    return module.NullDereferenceDetector


def make_result(detector_type, path: str, text: str, source_hash: str) -> dict:
    unit = SourceUnit(path, "cpp", text, source_hash, "complete")
    request = ScanRequest(
        "pinned-control:" + source_hash[:16],
        "fixture/a-null-pinned-controls",
        "synthetic-a-null-controls-v1",
        snapshot_digest((unit,)),
        "current-component:fixture/a-null-pinned-controls",
    )
    run = detector_type().detect(ScanContext(request, (unit,), {}), (unit,))
    return {
        "coverage": dict(run.file_outcomes).get(path),
        "run_status": run.status,
        "findings": [
            {
                "line": finding.line,
                "rule_id": finding.rule_id,
                "message": finding.message,
                "obligations": [
                    {"kind": item.kind, "status": item.status}
                    for item in finding.evidence_obligations
                ],
            }
            for finding in run.findings
        ],
        "limitations": list(run.limitations),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(__file__).with_name(
            "macro_template_cross_function_controls_before_after_20261019.json"
        ),
    )
    args = parser.parse_args()

    current_bytes = DETECTOR_PATH.read_bytes()
    current_hash = sha256(current_bytes)
    if current_hash != AFTER_SHA256:
        raise SystemExit(f"current detector hash mismatch: {current_hash}")
    current_source = current_bytes.decode("utf-8")
    before_detector = load_before_detector(current_source)

    manifest = json.loads(CONTROL_MANIFEST.read_text(encoding="utf-8"))
    inputs = []
    for item in manifest["units"]:
        fixture = ROOT / item["path"]
        data = fixture.read_bytes()
        source_hash = sha256(data)
        if source_hash != item["sha256"]:
            raise ValueError(f"existing control hash mismatch: {fixture}")
        inputs.append((item["path"], data.decode("utf-8"), source_hash, "existing-A-NULL-02-control"))

    for fixture in sorted(BOUNDARY_FIXTURES.glob("*.cpp")):
        data = fixture.read_bytes()
        inputs.append((fixture.relative_to(ROOT).as_posix(), data.decode("utf-8"), sha256(data), "new-boundary-control"))
    if len(inputs) != 22:
        raise ValueError(f"expected 22 controls, got {len(inputs)}")

    cases = []
    for path, text, source_hash, origin in inputs:
        cases.append(
            {
                "path": path,
                "source_sha256": source_hash,
                "control_origin": origin,
                "before": make_result(before_detector, path, text, source_hash),
                "after": make_result(NullDereferenceDetector, path, text, source_hash),
            }
        )

    summary = {
        phase: {
            "controls": len(cases),
            "finding_rows": sum(len(case[phase]["findings"]) for case in cases),
            "partial_files": sum(case[phase]["coverage"] == "partial" for case in cases),
            "complete_zero_finding_files": sum(
                case[phase]["coverage"] == "complete" and not case[phase]["findings"]
                for case in cases
            ),
        }
        for phase in ("before", "after")
    }
    report = {
        "schema_version": "ohscanner.a-null-boundary-controls-before-after-v1",
        "base_commit": BASE_COMMIT,
        "comparison_scope": "same 19 A-NULL-02 controls plus every tracked cpp_null_boundary fixture; detector-only change reconstructed from immediate pre-change source and current source",
        "detector": {
            "id": "ohscanner.cpp.null_dereference",
            "version": NullDereferenceDetector.version,
            "before_source_sha256": BEFORE_SHA256,
            "after_source_sha256": AFTER_SHA256,
        },
        "tooling": {
            "python": platform.python_version(),
            "mode": "in-process detector comparison; no external analyzer or product build context",
            "replay_command": "python research/evidence/cpp/a_null_03_unknown_return_20261018/replay_macro_boundary_controls.py",
        },
        "summary": summary,
        "interpretation": "Synthetic controls only. They validate conservative macro/template/cross-function coverage behavior and do not establish product CFG, vulnerability truth, attacker control, or accuracy.",
        "cases": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "output": str(args.output), "summary": summary}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
