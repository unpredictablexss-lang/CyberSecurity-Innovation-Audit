"""A one-hop relay out of an entry is read as a boundary only when it is guarded.

M2: the OpenHarmony stub shape documents `OnRemoteRequest` as a thin wrapper that
hands the request to `OnRemoteRequestInner`, with the interface-token comparison
living inside the inner function. Treating the wrapper's call as an unguarded
boundary reported a real guard as absent.

The relay is accepted only when the callee compares `ReadInterfaceToken()` against
an accepted descriptor identity at top level, leaves on mismatch, and does so
before it routes the request; and only when every argument is one of the caller's
own parameters. Each of those five conditions has a fixture that breaks exactly one
of them and keeps the candidate.
"""
import hashlib
import json
from pathlib import Path
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.fixture import snapshot_digest

BASE = Path(__file__).parent / "fixtures" / "ipc"
RULE = "ipc.relay.descriptor-boundary"


def run_detector(name):
    text = (BASE / name).read_text(encoding="utf-8")
    index = parse_source(text, language="cpp")
    unit = SourceUnit(name, "cpp", text, hashlib.sha256(text.encode()).hexdigest(),
                      index.parse_status)
    request = ScanRequest("ipc-relay-test", "fixture/ipc", "synthetic-ipc-v1",
                          snapshot_digest((unit,)), "current-component:fixture/ipc")
    context = ScanContext(request, (unit,), {"ast": {name: index.to_dict()}})
    return IpcInterfaceDetector().detect(context, context.units)


class RelayGuardTests(unittest.TestCase):
    def auth01(self, name):
        return [f for f in run_detector(name).findings if f.rule_id == RULE]

    def relay_only(self, name, symbol):
        """The candidate on the relay call, not on anything the callee does."""
        found = [f for f in self.auth01(name) if f.symbol.endswith(symbol)]
        self.assertEqual(len(found), 1, [f.message for f in found])
        return found[0]

    def kinds(self, finding):
        return {obligation.kind for obligation in finding.evidence_obligations}

    # --- the callee is the guard: the call site is not a boundary ---------------

    def test_token_checked_in_the_callee_before_dispatch_is_a_guard(self):
        self.assertEqual(self.auth01("relay_inner_guard_fixed.cpp"), [])

    def test_the_token_may_be_held_in_a_local_first(self):
        self.assertEqual(self.auth01("relay_inner_local_guard_fixed.cpp"), [])

    def test_an_earlier_wrong_interface_comparison_does_not_hide_the_guard(self):
        self.assertEqual(self.auth01("relay_inner_wrong_then_correct_fixed.cpp"), [])

    # --- the callee is not the guard: the call site stays a candidate ----------

    def test_a_callee_that_never_compares_the_token_leaves_the_relay_unguarded(self):
        finding = self.relay_only("relay_inner_no_guard_positive.cpp",
                                  "RelayInnerNoGuardStub::OnRemoteRequest")
        self.assertIn("OnRemoteRequestInner", finding.message)

    def test_a_check_after_the_dispatch_does_not_dominate_it(self):
        self.relay_only("relay_inner_after_dispatch_positive.cpp",
                        "RelayInnerAfterDispatchStub::OnRemoteRequest")

    def test_a_mismatch_branch_that_does_not_leave_is_not_a_rejection(self):
        self.relay_only("relay_inner_no_reject_positive.cpp",
                        "RelayInnerNoRejectStub::OnRemoteRequest")

    def test_a_check_nested_inside_another_condition_does_not_dominate(self):
        self.relay_only("relay_inner_nested_positive.cpp",
                        "RelayInnerNestedStub::OnRemoteRequest")

    def test_replacing_an_argument_makes_it_a_call_rather_than_a_relay(self):
        self.relay_only("relay_inner_substituted_positive.cpp",
                        "RelayInnerSubstitutedStub::OnRemoteRequest")

    def test_a_comparison_against_another_interface_is_kept_and_cited(self):
        finding = self.relay_only("relay_inner_wrong_interface_positive.cpp",
                                  "RelayInnerWrongInterfaceStub::OnRemoteRequest")
        self.assertIn("present but not accepted", finding.message)
        self.assertIn("IBar declared at relay_inner_wrong_interface_positive.cpp", finding.message)
        self.assertIn("this class implements IFoo (stated at", finding.message)
        self.assertIn("descriptor_identity_mismatch", self.kinds(finding))


class ManifestCoverageTests(unittest.TestCase):
    def test_every_relay_inner_fixture_is_in_the_manifest(self):
        manifest = json.loads((BASE / "manifest.json").read_text())
        declared = {item["file"] for item in manifest}
        on_disk = {path.name for path in BASE.glob("relay_inner_*.cpp")}
        declared_relay = {name for name in declared if name.startswith("relay_inner_")}
        self.assertEqual(on_disk, declared_relay)
        self.assertEqual(len(on_disk), 9)

    def test_the_expected_rule_matches_the_fixture_name(self):
        for item in json.loads((BASE / "manifest.json").read_text()):
            if not item["file"].startswith("relay_inner_"):
                continue
            self.assertTrue((BASE / item["file"]).is_file(), item["file"])
            if item["file"].endswith("_fixed.cpp"):
                self.assertIsNone(item["expected_rule"], item["file"])
            else:
                self.assertEqual(item["expected_rule"], RULE, item["file"])


if __name__ == "__main__":
    unittest.main()
