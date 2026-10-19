"""Behavior controls for C12 LoopEnd-to-LoopBegin audit metadata."""
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import patch

from src.ohscanner.detectors.ark_runtime import analysis
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from .support import unit


SEMANTICS = Path(__file__).parent / "fixtures" / "c10_semantics"


def fixture(name):
    return (SEMANTICS / name).read_text(encoding="utf-8")


def generated_filter(source, mode):
    """Put the real typed-array sink in generated control flow."""
    store = "StoreTypedArrayElement(glue, output, count, input, inputTag);"
    if store not in source:
        store = next(line for line in source.splitlines()
                     if "StoreTypedArrayElement(" in line)
    body = store
    if mode == "paired_backedge_allocation":
        start = next(line for line in source.splitlines() if "GateRef output = " in line)
        start_at = source.index(start)
        store_end = source.index(store, start_at) + len(store)
        body = source[start_at:store_end]
    if mode == "paired_backedge":
        control = ("Label again(GetEnvironment()); Jump(&again); LoopBegin(&again);\n" +
                   body + "\nLoopEnd(&again);")
    elif mode == "paired_backedge_allocation":
        control = ("Label again(GetEnvironment()); Jump(&again); LoopBegin(&again);\n" +
                   body + "\nLoopEnd(&again);")
    elif mode == "exit_control":
        control = ("Label again(GetEnvironment()); Label exit(GetEnvironment());\n" +
                   "Jump(&again); LoopBegin(&again);\n" + body +
                   "\nJump(&exit); Bind(&exit);")
    elif mode == "unresolved_backedge":
        control = ("Label again(GetEnvironment()); Jump(&again); LoopBegin(&again);\n" +
                   body + "\nLoopEnd(&missing);")
    else:
        raise AssertionError(mode)
    if mode == "paired_backedge_allocation":
        return source[:start_at] + control + source[store_end:]
    return source.replace(body, control, 1)


def analyze(source):
    return analyze_unit(unit(source, "ecmascript/compiler/typedarray_stub_builder.cpp"))


class C12LoopBackedgeObservationControls(unittest.TestCase):
    def without_loop_backedges(self, source):
        build_graph = analysis.build_graph

        def without_metadata(function, budget):
            return replace(build_graph(function, budget), loop_backedges=())

        with patch.object(analysis, "build_graph", side_effect=without_metadata):
            return analyze(source)

    def test_candidate_parent_requires_real_observation_and_backedge_is_unknown(self):
        parent = fixture("ibs5yg_parent.cpp")
        candidate = analyze(generated_filter(parent, "exit_control"))
        self.assertEqual([item.kind for item in candidate.observations], ["candidate"])
        self.assertEqual(candidate.observations[0].reason, "distinct_origin_with_type_changing_creation")

        looped = generated_filter(parent, "paired_backedge_allocation")
        result = analyze(looped)
        self.assertIn("unknown", [item.kind for item in result.observations])
        self.assertTrue(any(item.reason == "loop_allocation_identity_unmodeled"
                            for item in result.observations))
        self.assertFalse(any(item.kind in ("candidate", "matched", "confirmed", "reportable")
                             for item in result.observations))
        self.assertEqual((result.status, result.file_outcome), ("limited", "partial"))
        stripped = self.without_loop_backedges(looped)
        self.assertFalse(any(item.kind == "candidate" for item in stripped.observations))

    def test_fixed_and_safe_controls_do_not_gain_candidates(self):
        fixed_sink_only = generated_filter(fixture("ibs5yg_fixed.cpp"), "paired_backedge")
        fixed_sink_result = analyze(fixed_sink_only)
        self.assertIn("matched", [item.kind for item in fixed_sink_result.observations])
        self.assertNotIn("candidate", [item.kind for item in fixed_sink_result.observations])
        stripped_sink = self.without_loop_backedges(fixed_sink_only)
        self.assertEqual(stripped_sink.observations, fixed_sink_result.observations)

        parent_sink_only = generated_filter(fixture("ibs5yg_parent.cpp"), "paired_backedge")
        parent_sink_result = analyze(parent_sink_only)
        self.assertIn("candidate", [item.kind for item in parent_sink_result.observations])
        self.assertEqual(self.without_loop_backedges(parent_sink_only).observations,
                         parent_sink_result.observations)

        fixed = generated_filter(fixture("ibs5yg_fixed.cpp"), "paired_backedge_allocation")
        fixed_result = analyze(fixed)
        self.assertNotIn("candidate", [item.kind for item in fixed_result.observations])
        self.assertTrue(any(item.kind == "unknown" and
                            item.reason == "loop_allocation_identity_unmodeled"
                            for item in fixed_result.observations))
        self.assertEqual((fixed_result.status, fixed_result.file_outcome), ("limited", "partial"))
        stripped_fixed = self.without_loop_backedges(fixed)
        self.assertTrue(any(item.kind == "candidate" for item in stripped_fixed.observations))

        safe_source = fixture("safe_same_type.cpp")
        safe = generated_filter(safe_source, "paired_backedge")
        safe_result = analyze(safe)
        self.assertIn("matched", [item.kind for item in safe_result.observations])
        self.assertNotIn("candidate", [item.kind for item in safe_result.observations])

    def test_unresolved_backedge_stays_unknown_and_never_becomes_candidate(self):
        source = generated_filter(fixture("ibs5yg_parent.cpp"), "unresolved_backedge")
        result = analyze(source)
        self.assertFalse(any(item.kind in ("candidate", "matched", "confirmed", "reportable")
                             for item in result.observations))
        self.assertIn("unresolved_generated_edge", [item.reason for item in result.observations])
        self.assertTrue(result.limitations)
        self.assertEqual((result.status, result.file_outcome), ("limited", "partial"))


if __name__ == "__main__":
    unittest.main()
