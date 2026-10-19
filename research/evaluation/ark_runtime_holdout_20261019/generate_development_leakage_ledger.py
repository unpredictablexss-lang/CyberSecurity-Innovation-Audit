#!/usr/bin/env python3
"""Generate the local-development leakage ledger used to exclude holdout leakage."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

SCHEMA = "ohscanner.ark-holdout-development-leakage-ledger/v1"
DEFAULT_ROOTS = (
    "tests/fixtures/known_cases",
    "tests/detectors/ark_runtime/fixtures",
)


def canonical_hash(value: Any) -> str:
    data = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def file_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def repo_path(root: Path, path: Path) -> str:
    return path.relative_to(root).as_posix()


def source_rows(root: Path, paths: list[Path]) -> list[dict[str, Any]]:
    rows = []
    for path in sorted(set(paths)):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        rows.append({
            "reason": "development fixture/review artifact excluded from real holdout",
            "repository_path": repo_path(root, path),
            "source_identity": {"role": "development_artifact"},
            "bytes": path.stat().st_size,
            "sha256": file_hash(path),
        })
    return rows


def collect_case_ids(known_manifest: dict[str, Any], product_gate: dict[str, Any]) -> list[str]:
    ids = {row.get("case_id") for row in known_manifest.get("cases", []) if row.get("case_id")}
    ids.update(row.get("identity") for row in product_gate.get("reviewed_case_dispositions", []) if row.get("identity"))
    ids.update(row.get("case_id") for row in product_gate.get("ark_product_candidates", []) if row.get("case_id"))
    return sorted(str(value) for value in ids if value)


def build(root: Path, protocol_path: Path, known_manifest_path: Path, product_gate_path: Path, generated_at: str) -> dict[str, Any]:
    protocol = json.loads(protocol_path.read_text(encoding="utf-8"))
    known_manifest = json.loads(known_manifest_path.read_text(encoding="utf-8"))
    product_gate = json.loads(product_gate_path.read_text(encoding="utf-8"))
    paths: list[Path] = []
    for rel in DEFAULT_ROOTS:
        candidate = root / rel
        if candidate.is_dir():
            paths.extend(path for path in candidate.rglob("*") if path.is_file())
        elif candidate.is_file():
            paths.append(candidate)
    paths.extend([known_manifest_path, product_gate_path])
    review_identity = product_gate.get("source_review_identity", {})
    review_rel = review_identity.get("path")
    if review_rel and (root / review_rel).is_file():
        paths.append(root / review_rel)
    rows = source_rows(root, paths)
    case_ids = collect_case_ids(known_manifest, product_gate)
    selection_frame_sha256 = canonical_hash(protocol["sampling_frame"])
    body = {
        "schema": SCHEMA,
        "status": "COMPLETE_LOCAL_DEVELOPMENT_ARTIFACTS",
        "generated_at": generated_at,
        "protocol_file_sha256": file_hash(protocol_path),
        "selection_frame_sha256": selection_frame_sha256,
        "development_artifact_roots": [repo_path(root, root / rel) for rel in DEFAULT_ROOTS],
        "excluded_case_ids": case_ids,
        "excluded_sources": rows,
        "excluded_source_sha256": sorted({row["sha256"] for row in rows}),
        "case_set_commitment_sha256": canonical_hash(case_ids),
        "coverage": {
            "roots_complete": True,
            "known_case_manifest_sha256": file_hash(known_manifest_path),
            "product_gate_payload_sha256": product_gate["payload_sha256"],
            "limitations": [
                "Local development artifacts are complete for the listed roots.",
                "The ledger is not a real holdout sample and does not prove zero external leakage.",
                "Regenerate after preregistration if the frozen sampling frame changes."
            ],
        },
    }
    body["payload_sha256"] = canonical_hash(body)
    return body


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--known-manifest", type=Path, required=True)
    parser.add_argument("--product-gate", type=Path, required=True)
    parser.add_argument("--generated-at", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve()
    protocol_path = args.protocol.resolve()
    known_manifest_path = args.known_manifest.resolve()
    product_gate_path = args.product_gate.resolve()
    payload = build(root, protocol_path, known_manifest_path, product_gate_path, args.generated_at)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({
        "status": payload["status"],
        "excluded_case_ids": len(payload["excluded_case_ids"]),
        "excluded_sources": len(payload["excluded_sources"]),
        "payload_sha256": payload["payload_sha256"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
