from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.cpp.null_dereference_detector import NullDereferenceDetector
from src.ohscanner.fixture import snapshot_digest


BASE_COMMIT = "4593a7c9b6977eb81172d01b46cc59daf46f5d45"
BASE_DETECTOR_SHA256 = "fc8ece1ebf202e11c5eada43b3d2eee22f173fb4a486fa344b44370031887662"
DETECTOR_RELATIVE_PATH = "src/ohscanner/detectors/cpp/null_dereference_detector.py"
CONTROL_MANIFEST = ROOT / "research/tests/a_null_02_controls/control_manifest.json"
BOUNDARY_FIXTURES = ROOT / "tests/detectors/fixtures/cpp_null_boundary"
REPLAY_INPUT_SOURCES = (
    "research/evidence/cpp/a_null_03_unknown_return_20261018/replay_macro_controls_from_main.py",
    "src/ohscanner/detectors/cpp/null_dereference_detector.py",
    "src/ohscanner/contracts.py",
    "src/ohscanner/fixture.py",
    "src/ohscanner/detectors/catalog.py",
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_value(*args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True, timeout=10
    )
    return result.stdout.strip()


def load_base_detector():
    result = subprocess.run(
        ["git", "show", f"{BASE_COMMIT}:{DETECTOR_RELATIVE_PATH}"],
        cwd=ROOT,
        capture_output=True,
        check=True,
        timeout=10,
    )
    source = result.stdout
    actual_hash = sha256(source.replace(b"\r\n", b"\n"))
    if actual_hash != BASE_DETECTOR_SHA256:
        raise ValueError(f"base detector source hash mismatch: {actual_hash}")
    module_name = "null_dereference_detector_at_main_base"
    spec = importlib.util.spec_from_loader(module_name, loader=None)
    if spec is None:
        raise RuntimeError("could not create base detector module spec")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    exec(compile(source.decode("utf-8"), f"{BASE_COMMIT}:{DETECTOR_RELATIVE_PATH}", "exec"), module.__dict__)
    return module.NullDereferenceDetector


def run_one(detector_type, path: str, text: str, source_hash: str) -> dict:
    unit = SourceUnit(path, "cpp", text, source_hash, "complete")
    request = ScanRequest(
        "macro-control:" + source_hash[:16],
        "fixture/a-null-macro-controls",
        "synthetic-a-null-macro-controls-v1",
        snapshot_digest((unit,)),
        "current-component:fixture/a-null-macro-controls",
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
    parser.add_argument("--output", type=Path, required=True, help="New output path; existing files are never overwritten.")
    parser.add_argument(
        "--input-report",
        type=Path,
        help="Use only case paths/source hashes from a frozen report; its findings and labels are ignored.",
    )
    args = parser.parse_args()

    if args.output.exists():
        raise ValueError(f"refusing to overwrite existing replay output: {args.output}")

    current_source = (ROOT / DETECTOR_RELATIVE_PATH).read_bytes()
    current_hash = sha256(current_source.replace(b"\r\n", b"\n"))
    implementation_sources = {
        path: sha256((ROOT / path).read_bytes().replace(b"\r\n", b"\n"))
        for path in REPLAY_INPUT_SOURCES
    }
    working_tree_status = git_value("status", "--porcelain")
    base_detector = load_base_detector()
    inputs = []
    if args.input_report:
        input_report = json.loads(args.input_report.read_text(encoding="utf-8"))
        for item in input_report.get("cases", []):
            relative = Path(item["path"])
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError("input report contains a non-canonical fixture path")
            path = (ROOT / relative).resolve()
            if not path.is_relative_to(ROOT.resolve()):
                raise ValueError("input report fixture escaped repository root")
            data = path.read_bytes()
            actual = sha256(data)
            if actual != item.get("source_sha256"):
                raise ValueError(f"input-report fixture hash mismatch: {path}")
            origin = item.get("control_origin")
            if origin not in {"A-NULL-02-control", "macro-template-cross-function-boundary"}:
                raise ValueError(f"unsupported control origin: {origin!r}")
            inputs.append((path.relative_to(ROOT).as_posix(), data.decode("utf-8"), actual, origin))
    else:
        manifest = json.loads(CONTROL_MANIFEST.read_text(encoding="utf-8"))
        for item in manifest["units"]:
            path = ROOT / item["path"]
            data = path.read_bytes()
            actual = sha256(data)
            if actual != item["sha256"]:
                raise ValueError(f"control fixture hash mismatch: {path}")
            inputs.append((item["path"], data.decode("utf-8"), actual, "A-NULL-02-control"))

        for path in sorted(BOUNDARY_FIXTURES.glob("*.cpp")):
            data = path.read_bytes()
            inputs.append((path.relative_to(ROOT).as_posix(), data.decode("utf-8"), sha256(data), "macro-template-cross-function-boundary"))
    if len(inputs) != 25:
        raise ValueError(f"expected 25 fixed controls, got {len(inputs)}")
    if len({item[0] for item in inputs}) != len(inputs):
        raise ValueError("input controls contain duplicate fixture paths")

    cases = []
    for path, text, source_hash, origin in inputs:
        cases.append(
            {
                "path": path,
                "source_sha256": source_hash,
                "control_origin": origin,
                "before": run_one(base_detector, path, text, source_hash),
                "after": run_one(NullDereferenceDetector, path, text, source_hash),
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
        "schema_version": "ohscanner.a-null-macro-controls-before-after-v1",
        "base_commit": BASE_COMMIT,
        "working_tree_revision": git_value("rev-parse", "HEAD"),
        "working_tree_status_sha256": sha256(git_value("status", "--porcelain").encode("utf-8")),
        "comparison_scope": "same 19 A-NULL-02 controls and all 6 fixed cpp_null_boundary controls; main-base detector compared with current working detector on identical source bytes",
        "detector": {
            "id": NullDereferenceDetector.detector_id,
            "before_version": base_detector.version,
            "after_version": NullDereferenceDetector.version,
            "before_source_sha256": BASE_DETECTOR_SHA256,
            "after_source_sha256": current_hash,
            "catalog_source_sha256": implementation_sources["src/ohscanner/detectors/catalog.py"],
        },
        "execution_source_snapshot": {
            "working_tree_revision": git_value("rev-parse", "HEAD"),
            "working_tree_status_sha256": sha256(working_tree_status.encode("utf-8")),
            "source_sha256_by_path": implementation_sources,
            "scope": "direct replay script, detector, contracts, fixture digest helper, and catalog; not a complete repository or Python environment attestation",
        },
        "tooling": {
            "python": platform.python_version(),
            "git": subprocess.run(["git", "--version"], cwd=ROOT, capture_output=True, text=True, check=True, timeout=5).stdout.strip(),
            "mode": "in-process detector replay; no external analyzer or product build context",
            "replay_command": " ".join(sys.argv),
            "input_mode": "frozen-report-source-identities-only" if args.input_report else "development-control-manifest",
        },
        "summary": summary,
        "interpretation": "This is a pinned synthetic-control comparison, not product CFG validation, vulnerability ground truth, or an accuracy estimate. Macro findings remain candidates and macro/compile context obligations remain unknown/missing.",
        "cases": cases,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "output": str(args.output), "summary": summary}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
