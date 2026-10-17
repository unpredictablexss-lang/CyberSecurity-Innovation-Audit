from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.ohscanner.holdout import save_json


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    raw_path = args.run_dir / "results.json"
    raw = raw_path.read_bytes()
    compressed = gzip.compress(raw, compresslevel=9, mtime=0)
    gzip_path = args.run_dir / "results.json.gz"
    gzip_path.write_bytes(compressed)
    delivery = {
        "schema_version": 1,
        "kind": "ohscanner.independent-holdout-results-delivery.v1",
        "raw_artifact": {
            "path": "results.json",
            "bytes": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "retention": "local generated evidence; not committed due size",
        },
        "compressed_artifact": {
            "path": "results.json.gz",
            "bytes": len(compressed),
            "sha256": hashlib.sha256(compressed).hexdigest(),
            "compression": "gzip -9, deterministic mtime=0",
            "completeness": "lossless complete raw results",
        },
    }
    save_json(args.run_dir / "results-delivery-manifest.json", delivery)
    run_manifest_path = args.run_dir / "run_manifest.json"
    run_manifest = json.loads(run_manifest_path.read_text(encoding="utf-8"))
    run_manifest["artifacts"]["results.json.gz"] = delivery["compressed_artifact"]["sha256"]
    run_manifest["artifacts"]["results-delivery-manifest.json"] = sha256(
        args.run_dir / "results-delivery-manifest.json"
    )
    run_manifest["results_delivery"] = {
        "git_artifact": "results.json.gz",
        "raw_results_retained_locally": True,
        "raw_results_committed": False,
        "reason": "37 MB generated JSON is losslessly compressed for repository delivery",
    }
    save_json(run_manifest_path, run_manifest)
    print(json.dumps(delivery, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
