"""The descriptor comparison is read as an interface identity, not as a call.

M1: `analysis.py` accepted `X::GetDescriptor()` only when X was the enclosing
class, so the real stub shape -- `FooStub : public IRemoteStub<IFoo>` comparing
against `IFoo::GetDescriptor()` -- had its guard discarded and its handler
reported as unguarded. The identity now comes from the class's own base clause.

These tests pin the three outcomes (consistent / mismatched / unresolved) and the
four ways a comparison that is present still is not a guard: no comparison, no
rejecting branch, guard after the operation, guard on one branch only.
"""
import hashlib
import json
from pathlib import Path
import unittest

from src.parser.ast import parse_source
from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.detectors.interface.entry_index import EntryIndex
from src.ohscanner.detectors.interface.models import IpcPolicy
from src.ohscanner.fixture import snapshot_digest

BASE = Path(__file__).parent / "fixtures" / "ipc"
RULE = "ipc.relay.descriptor-boundary"


def text_of(name):
    return (BASE / name).read_text(encoding="utf-8")


def run_detector(name, text=None):
    text = text if text is not None else text_of(name)
    index = parse_source(text, language="cpp")
    unit = SourceUnit(name, "cpp", text, hashlib.sha256(text.encode()).hexdigest(),
                      index.parse_status)
    request = ScanRequest("ipc-descriptor-test", "fixture/ipc", "synthetic-ipc-v1",
                         snapshot_digest((unit,)), "current-component:fixture/ipc")
    context = ScanContext(request, (unit,), {"ast": {name: index.to_dict()}})
    return IpcInterfaceDetector().detect(context, context.units)


class Unit:
    """The four fields the entry index reads; no runner needed."""

    def __init__(self, path, text):
        self.path = path
        self.language = "cpp"
        self.text = text
        self.parse_status = "complete"


def interfaces_of(name, owner):
    index = EntryIndex((Unit(name, text_of(name)),), IpcPolicy())
    return index.implemented_interfaces(owner)


class IdentityResolutionTests(unittest.TestCase):
    def test_interface_identity_comes_from_the_base_clause(self):
        found = interfaces_of("descriptor_interface_fixed.cpp", "DescriptorInterfaceStub")
        self.assertEqual([item.name for item in found], ["IFoo"])
        self.assertEqual(found[0].file, "descriptor_interface_fixed.cpp")
        self.assertEqual(found[0].line, 10)   # the `class ... : public IRemoteStub<IFoo>`

    def test_interface_without_an_i_prefix_is_not_guessed_by_name(self):
        found = interfaces_of("descriptor_no_prefix_fixed.cpp", "DescriptorNoPrefixStub")
        self.assertEqual([item.name for item in found], ["OnPermissionUsedRecordCallback"])

    def test_inherited_interface_is_found_through_an_intermediate_base(self):
        found = interfaces_of("descriptor_inherited_fixed.cpp", "DescriptorInheritedStub")
        self.assertEqual([item.name for item in found], ["IFoo"])

    def test_a_class_the_sources_do_not_declare_yields_no_identity(self):
        self.assertEqual(interfaces_of("descriptor_unresolved_positive.cpp",
                                       "DescriptorUnresolvedStub"), ())


class DescriptorGuardTests(unittest.TestCase):
    def auth01(self, name):
        run = run_detector(name)
        return [f for f in run.findings if f.rule_id == RULE]

    def only(self, name):
        found = self.auth01(name)
        self.assertEqual(len(found), 1, [f.message for f in found])
        return found[0]

    def kinds(self, finding):
        return {obligation.kind for obligation in finding.evidence_obligations}

    # --- the identity is this transaction's: the comparison is a guard ---------

    def test_qualified_interface_comparison_is_accepted(self):
        self.assertEqual(self.auth01("descriptor_interface_fixed.cpp"), [])

    def test_interface_without_an_i_prefix_is_accepted(self):
        self.assertEqual(self.auth01("descriptor_no_prefix_fixed.cpp"), [])

    def test_inherited_interface_is_accepted(self):
        self.assertEqual(self.auth01("descriptor_inherited_fixed.cpp"), [])

    # --- the identity is another interface: a candidate, both sides cited ------

    def test_wrong_interface_cites_the_compared_and_the_implemented_identity(self):
        finding = self.only("descriptor_wrong_interface_positive.cpp")
        self.assertIn("mismatched", finding.message)
        self.assertIn("IBar declared at descriptor_wrong_interface_positive.cpp", finding.message)
        self.assertIn("this class implements IFoo (stated at", finding.message)
        self.assertIn("descriptor_identity_mismatch", self.kinds(finding))

    def test_unrelated_class_with_the_same_method_name_is_a_mismatch(self):
        finding = self.only("descriptor_unrelated_positive.cpp")
        self.assertIn("Unrelated declared at", finding.message)
        self.assertIn("descriptor_identity_mismatch", self.kinds(finding))

    # --- the identity is not determined: unknown, and said to be unknown -------

    def test_alias_base_is_unknown_rather_than_guessed(self):
        finding = self.only("descriptor_alias_positive.cpp")
        self.assertIn("not determined", finding.message)
        self.assertNotIn("mismatched", finding.message)
        self.assertIn("descriptor_identity_unresolved", self.kinds(finding))

    def test_undeclared_class_is_unknown_even_when_the_compared_name_resolves(self):
        finding = self.only("descriptor_unresolved_positive.cpp")
        self.assertIn("IElsewhere declared at descriptor_unresolved_positive.cpp", finding.message)
        self.assertIn("no interface is stated for DescriptorUnresolvedStub", finding.message)
        self.assertIn("descriptor_identity_unresolved", self.kinds(finding))

    # --- a comparison that is present but not a guard --------------------------

    def test_calling_get_descriptor_without_comparing_is_not_a_guard(self):
        finding = self.only("descriptor_call_only_positive.cpp")
        self.assertNotIn("Guard seen", finding.message)
        self.assertNotIn("descriptor_identity_mismatch", self.kinds(finding))

    def test_interface_is_accepted_but_a_journal_branch_is_not_a_rejection(self):
        # The identity is right, so the reason is dominance, not identity: the
        # mismatch branch does not leave the transaction, so both paths reach the
        # handler and no guard dominates.
        finding = self.only("descriptor_no_reject_positive.cpp")
        self.assertNotIn("descriptor_identity_mismatch", self.kinds(finding))

    def test_guard_after_the_operation_does_not_cover_it(self):
        finding = self.only("descriptor_after_positive.cpp")
        self.assertEqual(finding.line, 15)          # the OnCallback() call
        self.assertNotIn("descriptor_identity_mismatch", self.kinds(finding))

    def test_guard_on_one_branch_leaves_the_other_unguarded(self):
        run = run_detector("descriptor_one_branch_positive.cpp")
        guarded = [f for f in run.findings if f.rule_id == RULE and f.symbol.endswith("HandleMessage")]
        unguarded = [f for f in run.findings if f.rule_id == RULE and f.symbol.endswith("OnRemoteRequest")]
        # The guarded branch reaches its handler with the descriptor established;
        # the other branch reaches OnCallback() without one.
        self.assertEqual(guarded, [])
        self.assertEqual(len(unguarded), 1)


class ManifestCoverageTests(unittest.TestCase):
    def test_every_descriptor_fixture_is_in_the_manifest(self):
        declared = {item["file"] for item in json.loads((BASE / "manifest.json").read_text())}
        on_disk = {path.name for path in BASE.glob("descriptor_*.cpp")}
        self.assertEqual(on_disk - declared, set())


if __name__ == "__main__":
    unittest.main()
