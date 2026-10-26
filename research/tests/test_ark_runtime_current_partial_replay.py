from __future__ import annotations

import hashlib
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from src.ohscanner.contracts import SourceUnit
from research.full_scan_20261018.lanes.c.analysis import analyze_unit
from research.full_scan_20261018.lanes.c.model import RuntimeTypeModel


SOURCE_DIR = ROOT / "research/experiments/ark-runtime-exact-source-20261018/sources"
TARGET = "ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp"
PROFILES = {
    "parent": (
        "type-origin-parent.cpp",
        "830e85b40240677039719fcbf14f721ad3b19050",
        "054451b1be4f39254d56a1683cc9d1c1b5e55018",
        "847d54f51e384368f49d4e2dd45e900ce6d305a142638a02dda83e3cc6eca422",
    ),
    "fix": (
        "type-origin-fix.cpp",
        "a0e30483ab3e4aead67ecfb5c708489915e447f9",
        "95f54f2875f401afe3167c62f8c1e7799782be8c",
        "8751b09dfc53d57338d0937d9c120574cdd4c7dfedd417fda41ccc399be7f74e",
    ),
}


def replay(profile):
    filename, _commit, expected_blob, expected_sha = PROFILES[profile]
    raw = (SOURCE_DIR / filename).read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    digest = hashlib.sha256(raw).hexdigest()
    if (blob, digest) != (expected_blob, expected_sha):
        raise AssertionError(f"source object mismatch for {profile}: {blob} {digest}")
    unit = SourceUnit(TARGET, "cpp", raw.decode("utf-8"), digest, "partial")
    return analyze_unit(unit, model=RuntimeTypeModel(), research_partial=True)


class CurrentPartialReplayTests(unittest.TestCase):
    """Private partial-AST regression only; this never calls the public Runner."""

    def test_parent_candidate_and_fix_unknown_remain_partial(self):
        parent = replay("parent")
        self.assertEqual(parent.file_outcome, "partial")
        self.assertEqual(parent.model_digest, RuntimeTypeModel().digest)
        parent_candidates = [item for item in parent.observations if item.kind == "candidate"]
        self.assertEqual(len(parent_candidates), 1)
        self.assertEqual(parent_candidates[0].line, 1498)
        self.assertEqual(parent_candidates[0].reason, "different_origin_with_species_creation")
        self.assertIn("parse_dependency_contamination_unknown", parent.limitations)
        self.assertIn("production_runner_not_admitted", parent.limitations)

        fixed = replay("fix")
        self.assertEqual(fixed.file_outcome, "partial")
        self.assertFalse(any(item.kind == "candidate" for item in fixed.observations))
        fix_unknowns = [item for item in fixed.observations if item.kind == "unknown"]
        self.assertEqual(len(fix_unknowns), 1)
        self.assertEqual(fix_unknowns[0].line, 1499)
        self.assertEqual(fix_unknowns[0].reason, "new_typed_array_type_read_before_exception_check")
        self.assertIn("parse_dependency_contamination_unknown", fixed.limitations)
        self.assertIn("production_runner_not_admitted", fixed.limitations)


if __name__ == "__main__":
    unittest.main()
