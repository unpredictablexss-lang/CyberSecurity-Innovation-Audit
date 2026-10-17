from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.holdout import save_json, summarize_predictions, verify_freeze


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_lf(path: Path) -> None:
    path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    verify_freeze(manifest)
    for name in ("results.json", "predictions.json"):
        normalize_lf(args.run_dir / name)
    run_manifest_path = args.run_dir / "run_manifest.json"
    run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
    for name in ("results.json", "predictions.json"):
        actual = sha256(args.run_dir / name)
        if run_manifest["artifacts"][name] != actual:
            raise ValueError(name + " changed after the frozen detector run")
    predictions = json.loads((args.run_dir / "predictions.json").read_text(encoding="utf-8"))
    metrics = summarize_predictions(manifest, predictions)
    metrics_sha = save_json(args.run_dir / "metrics.json", metrics)
    run_manifest["artifacts"]["metrics.json"] = metrics_sha
    run_manifest["metrics_recomputed_without_detector_execution"] = True
    run_manifest["metrics_recompute_reason"] = (
        "Fail-closed semantics were corrected so unknown samples never become FN and "
        "families without complete paired coverage do not publish Precision/Recall/F1."
    )
    run_manifest["aborted_preflight"] = {
        "detector_execution": "one sample reached run_all before a result-serialization TypeError",
        "outputs_retained": False,
        "used_for_metrics": False,
        "detector_tuning": False,
    }
    save_json(run_manifest_path, run_manifest)
    print(json.dumps(run_manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
