from __future__ import annotations

import hashlib
import json
from pathlib import Path

from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.model import RULE_ID, RuntimeTypeModel
from tests.detectors.ark_runtime.support import unit

ROOT = Path.cwd()
FIXTURE_ROOT = ROOT / "research/experiments/ark_runtime/c8_known_vulnerability_replay_20261019/fixtures"
CONTROLS = (
    ("C8-TO-POS-001", "type_origin_positive.cpp", "candidate"),
    ("C8-TO-FIX-001", "type_origin_fixed.cpp", "matched"),
    ("C8-TO-SAFE-001", "type_origin_safe_control.cpp", "matched"),
    ("C8-TO-UNR-001", "type_origin_unrelated.cpp", "not_analyzed"),
    ("C8-TO-UNKNOWN-001", "type_origin_unknown_001.cpp", "unknown"),
    ("C8-TO-UNKNOWN-002", "type_origin_unknown_002.cpp", "unknown"),
    ("C8-TO-UNKNOWN-003", "type_origin_unknown_003.cpp", "unknown"),
    ("C8-TO-UNKNOWN-004", "type_origin_unknown_004.cpp", "unknown"),
    ("C8-TO-UNKNOWN-005", "type_origin_unknown_005.cpp", "unknown"),
    ("C8-TO-UNKNOWN-006", "type_origin_unknown_006.cpp", "unknown"),
)


def identity(path: Path) -> dict:
    data = path.read_bytes()
    return {
        "path": path.relative_to(ROOT).as_posix(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "git_blob": "unknown_untracked",
    }


rows = []
for control_id, name, expected in CONTROLS:
    path = FIXTURE_ROOT / name
    source = path.read_text(encoding="utf-8")
    result = analyze_unit(unit(source))
    kinds = [item.kind for item in result.observations]
    rows.append({
        "control_id": control_id,
        "expected": expected,
        "actual_kinds": kinds,
        "actual_status": result.status,
        "file_outcome": result.file_outcome,
        "reasons": [item.reason for item in result.observations],
        "model_digest": result.model_digest,
        "source": identity(path),
        "assertion_passed": (kinds == [expected] if expected != "not_analyzed" else not kinds),
    })

print(json.dumps({
    "schema": "c9-type-origin-source-bound-regression/v1",
    "rule_id": RULE_ID,
    "base_head": "7af25f5ced471e5d6acc8cf5efd4c696275ce940",
    "base_tree": "11f53fe00d79d477c383e7e9b49ad3b1adcae86c",
    "e4e_review_ref": "origin/codex/c-line-ark-runtime-20261018",
    "e4e_review_commit": "e4e0761501a83ac25cc67d04c527eefe9f4a1b50",
    "e4e_review_blob": "dbedea677c8dc70c1b0066c7bc52df27bcff06ea",
    "scope": "synthetic Ark Runtime type-origin controls; no product binding",
    "profile": RuntimeTypeModel().build_profile,
    "controls": rows,
}, ensure_ascii=False, indent=2))
