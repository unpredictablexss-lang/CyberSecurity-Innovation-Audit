#!/usr/bin/env python3
"""Read-only structural check restricted to this C5 preparation directory.

This is not a test suite or an evaluation verifier. It intentionally opens no
files outside its own directory and cannot inspect source, escrow, labels,
predictions, reviewer workspaces, or any holdout data.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent


def load_json(name: str) -> dict:
    path = ROOT / name
    if path.parent != ROOT:
        raise SystemExit(f"refusing path outside C5 directory: {name}")
    with path.open("r", encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise SystemExit(f"expected JSON object: {name}")
    return value


def main() -> int:
    public_register = load_json("public_development_exposure_register.json")
    gates = load_json("admission_gate_register.template.json")
    artifacts = load_json("frozen_artifact_register.template.json")
    load_json("family_source_exclusion_ledger.schema.json")

    if public_register.get("document_status") != "preparation_only":
        raise SystemExit("public exposure register is not preparation_only")
    if public_register.get("sample_count") != 0:
        raise SystemExit("nonzero sample count in public exposure register")
    if gates.get("document_status") != "preparation_only":
        raise SystemExit("admission register is not preparation_only")
    counts = tuple(gates.get(key) for key in ("sample_count", "label_count", "prediction_count", "score_count"))
    if counts != (0, 0, 0, 0):
        raise SystemExit(f"nonzero or missing outcome counts: {counts}")
    if len(gates.get("gates", [])) != 10:
        raise SystemExit("expected the ten ordered admission gates")
    if any(gate.get("status") in {"passed", "approved", "cleared"} for gate in gates["gates"]):
        raise SystemExit("preparation template must not contain a passed gate")
    if artifacts.get("document_status") != "preparation_only":
        raise SystemExit("artifact register is not preparation_only")
    if any(item.get("sha256") is not None for item in artifacts.get("artifacts", [])):
        raise SystemExit("preparation template unexpectedly contains a frozen digest")

    csv_path = ROOT / "family_source_exclusion_ledger.template.csv"
    if csv_path.parent != ROOT:
        raise SystemExit("refusing CSV path outside C5 directory")
    with csv_path.open("r", encoding="utf-8", newline="") as stream:
        first = stream.readline().rstrip("\r\n")
        if not first.startswith("# PREPARATION_ONLY"):
            raise SystemExit("CSV template lost its non-ingestible preparation marker")
        rows = list(csv.DictReader(stream))
    if rows:
        raise SystemExit("family exclusion template must contain zero records")

    print("C5 preparation structure: valid")
    print("scope: this directory only; no evaluation or admin data opened")
    print(f"gates: {len(gates['gates'])}; counts: samples/labels/predictions/scores={counts}")
    print("family ledger records: 0; frozen artifact digests: 0")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
