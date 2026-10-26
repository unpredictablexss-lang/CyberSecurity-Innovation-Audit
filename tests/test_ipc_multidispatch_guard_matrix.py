"""Independent per-sink matrix for descriptor guards and multiple dispatches.

Semantic oracle (written without consulting relay_guard implementation): a sink
is protected only by a matching IFoo descriptor check whose mismatch path exits
before that sink. A later check cannot protect an earlier sink, a check on only
one branch cannot protect its sibling, and a nonunique helper target cannot be
used to suppress the call site by guessing which body runs.
"""
import hashlib
from pathlib import Path
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest


FIXTURES = Path(__file__).parent / "fixtures" / "ipc" / "t5_multidispatch"
RULE = "ipc.relay.descriptor-boundary"


def run_fixture(filename):
    text = (FIXTURES / filename).read_text(encoding="utf-8")
    path = "t5_multidispatch/" + filename
    index = parse_source(text, language="cpp")
    unit = SourceUnit(path, "cpp", text, hashlib.sha256(text.encode()).hexdigest(),
                      index.parse_status)
    request = ScanRequest("ipc-t5-" + filename, "fixture/ipc", "synthetic-t5-v1",
                          snapshot_digest((unit,)), "current-component:fixture/ipc")
    context = ScanContext(request, (unit,), {"ast": {path: index.to_dict()}})
    return text, IpcInterfaceDetector().detect(context, (unit,))


def callback_lines(text):
    return [number for number, line in enumerate(text.splitlines(), 1)
            if "OnCallback();" in line]


def sink_lines(text, run):
    return sorted(finding.line for finding in run.findings
                  if finding.rule_id == RULE
                  and finding.symbol.endswith("::OnRemoteRequestInner"))


class MultiDispatcherGuardMatrixTests(unittest.TestCase):
    def assert_sink_oracle(self, filename, expected_callback_indexes):
        text, run = run_fixture(filename)
        self.assertEqual(run.status, "completed")
        self.assertEqual(parse_source(text, language="cpp").parse_status, "complete")
        sinks = callback_lines(text)
        expected = [sinks[index] for index in expected_callback_indexes]
        self.assertEqual(sink_lines(text, run), expected,
                         [(f.line, f.symbol, f.message) for f in run.findings])

    def test_matching_guard_before_all_switches_protects_each_sink(self):
        # Two dispatchers share one prior, rejecting interface guard.
        self.assert_sink_oracle("guard_before_all.cpp", [])

    def test_guard_between_switches_protects_only_the_later_sink(self):
        # First effect precedes the guard; second effect is dominated by it.
        self.assert_sink_oracle("dispatch_guard_dispatch.cpp", [0])

    def test_guard_after_both_switches_protects_neither_sink(self):
        self.assert_sink_oracle("both_dispatches_before_guard.cpp", [0, 1])

    def test_wrong_interface_check_does_not_protect_first_sink(self):
        # The first check names IBar and does not reject. A later IFoo guard
        # separates the dispatches, so only the first sink remains a candidate.
        self.assert_sink_oracle("wrong_then_correct_between.cpp", [0])

    def test_branch_local_guard_does_not_protect_the_sibling_dispatch(self):
        # The guarded arm is safe; the else-arm sink is unguarded.
        self.assert_sink_oracle("branch_only_guard.cpp", [1])

    def test_a_conditional_return_in_the_mismatch_block_leaves_a_dispatch_path(self):
        # A mismatch exits only for code 99; code 1 still reaches this sink.
        self.assert_sink_oracle("conditional_mismatch_return.cpp", [0])

    def test_an_unconditional_return_in_the_mismatch_block_protects_the_sink(self):
        # The same conditional return plus an unconditional return makes every
        # descriptor mismatch leave before dispatch.
        self.assert_sink_oracle("unconditional_mismatch_return.cpp", [])

    def test_nonunique_helper_keeps_the_entry_candidate_without_guessing_a_body(self):
        text, run = run_fixture("ambiguous_helper.cpp")
        self.assertEqual(run.status, "completed")
        sinks = callback_lines(text)
        self.assertEqual(sink_lines(text, run), [])
        entry = [finding for finding in run.findings if finding.rule_id == RULE
                 and finding.symbol.endswith("::OnRemoteRequest")]
        self.assertEqual(len(entry), 1, [(f.line, f.symbol, f.message) for f in run.findings])
        self.assertEqual(entry[0].line,
                         next(number for number, line in enumerate(text.splitlines(), 1)
                              if "return OnRemoteRequestInner(" in line))
        self.assertIn("Entry=", entry[0].message)
        self.assertNotIn("Guarded", entry[0].message)


if __name__ == "__main__":
    unittest.main()
