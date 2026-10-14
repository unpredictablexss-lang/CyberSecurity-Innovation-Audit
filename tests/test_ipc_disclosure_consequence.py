"""Regression for the consequence dimension of IPC candidates.

The mechanism rules say how a trust boundary fails (`ipc.auth.missing`,
`ipc.parcel.copy-range`, ...). This dimension says what the failure can expose,
which is scored separately: completeness, and CWE accuracy, where the mechanism
CWE and the consequence CWE are different answers.

The point of these tests is that the consequence follows the *operation*, not the
family. Four of the twelve verified S2 pairs name information disclosure as the
official impact and they sit in three different families, so a read of sensitive
data must promote the consequence whichever mechanism failed.
"""
import hashlib
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest, SourceUnit
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.detectors.interface.models import (
    DISCLOSURE_CALLS,
    IMPACT_BY_RULE,
    IMPACT_DESCRIPTION,
    consequence_for,
)
from src.ohscanner.fixture import snapshot_digest
from src.parser.ast import parse_source

PREAMBLE = """#pragma once
#include <cstdint>
#include <cstring>
#include <string>
struct MessageOption {};
struct MessageParcel {
 std::u16string ReadInterfaceToken(); int ReadInt32(); unsigned ReadUint32();
 const char *ReadBuffer(unsigned);
};
struct IPCSkeleton { static unsigned GetCallingTokenID(); static int GetCallingUid(); };
struct AccessTokenKit { static int VerifyAccessToken(unsigned,const char *); };
constexpr int PERMISSION_GRANTED=0; constexpr int PERMISSION_DENIED=-1;
std::u16string GetDescriptor(); unsigned GetSelfTokenID(); int getuid();
void StartAbility(); void OnCallback(); void DeleteUserData(int);
struct Stub { int OnRemoteRequest(uint32_t code,MessageParcel &data,MessageParcel &reply,MessageOption &option); };
"""


def run_snippet(body):
    text = PREAMBLE + "\n" + body
    index = parse_source(text, language="cpp")
    unit = SourceUnit("sample.cpp", "cpp", text,
                      hashlib.sha256(text.encode()).hexdigest(), index.parse_status)
    request = ScanRequest("ipc-consequence", "fixture/ipc", "synthetic-consequence-v1",
                          snapshot_digest((unit,)), "current-component:fixture/ipc")
    context = ScanContext(request, (unit,), {"ast": {"sample.cpp": index.to_dict()}})
    return IpcInterfaceDetector().detect(context, (unit,))


def finding_for(run, rule_id):
    matches = [finding for finding in run.findings if finding.rule_id == rule_id]
    if not matches:
        raise AssertionError("no finding for " + rule_id + "; got "
                             + repr(sorted({f.rule_id for f in run.findings})))
    return matches[0]


def obligation_kinds(finding):
    return {obligation.kind for obligation in finding.evidence_obligations}


class ConsequenceCatalogueTests(unittest.TestCase):
    def test_a_read_call_promotes_the_consequence_whatever_the_rule(self):
        for rule in ("ipc.auth.missing", "ipc.auth.caller-class", "ipc.relay.descriptor-boundary",
                     "ipc.parcel.copy-range"):
            with self.subTest(rule=rule):
                impact, cwe, basis = consequence_for(rule, ("GetPasteData",))
                self.assertEqual(impact, "information_disclosure")
                self.assertEqual(cwe, "CWE-200")
                self.assertEqual(basis, "GetPasteData")

    def test_a_non_read_call_falls_back_to_the_rule_baseline(self):
        impact, cwe, _basis = consequence_for("ipc.auth.missing", ("Install",))
        self.assertEqual(impact, IMPACT_BY_RULE["ipc.auth.missing"])
        self.assertNotEqual(cwe, "CWE-200")

    def test_an_out_of_bounds_read_keeps_its_own_consequence(self):
        impact, cwe, _basis = consequence_for("ipc.parcel.copy-range", ("memcpy",))
        self.assertEqual(impact, "out_of_bounds_read")
        self.assertEqual(cwe, "CWE-125")

    def test_an_unknown_rule_does_not_invent_a_consequence(self):
        impact, cwe, _basis = consequence_for("ipc.something.new", ())
        self.assertEqual(impact, "unknown")
        self.assertEqual(cwe, "")

    def test_every_disclosure_call_is_a_reviewed_catalogue_entry(self):
        # The catalogue must be explicit, not inferred; a typo would silently
        # disable the dimension for one API.
        self.assertTrue(DISCLOSURE_CALLS)
        for name in ("GetPasteData", "ReadFile", "ReadUserData", "GetPermissionUsedRecordsAsync"):
            self.assertIn(name, DISCLOSURE_CALLS)


class DetectorConsequenceTests(unittest.TestCase):
    ENTRY = ("int Stub::OnRemoteRequest(uint32_t code,MessageParcel &data,"
             "MessageParcel &reply,MessageOption &option) {\n%s\n}\n")

    def test_auth02_read_reports_information_disclosure(self):
        run = run_snippet(self.ENTRY % "return GetPasteData();")
        finding = finding_for(run, "ipc.auth.missing")
        self.assertIn("information_disclosure", finding.message)
        self.assertIn("CWE-200", finding.message)
        self.assertIn("GetPasteData", finding.message)
        # The mechanism CWE on the finding is unchanged: the consequence is a
        # second, different answer, not a replacement.
        self.assertEqual(finding.candidate_cwe, "CWE-862")
        self.assertIn("consequence", obligation_kinds(finding))

    def test_auth03_read_reports_information_disclosure_through_a_second_mechanism(self):
        run = run_snippet(self.ENTRY % "return IsAllowedUsingPermission();")
        finding = finding_for(run, "ipc.auth.caller-class")
        self.assertIn("information_disclosure", finding.message)
        self.assertEqual(finding.candidate_cwe, "CWE-863")

    def test_auth02_non_read_call_does_not_claim_disclosure(self):
        run = run_snippet(self.ENTRY % "return Install();")
        finding = finding_for(run, "ipc.auth.missing")
        self.assertNotIn("CWE-200", finding.message)
        self.assertIn(IMPACT_BY_RULE["ipc.auth.missing"], finding.message)
        self.assertIn("consequence", obligation_kinds(finding))

    def test_auth01_relay_keeps_the_boundary_consequence(self):
        run = run_snippet(self.ENTRY % "OnCallback();\nreturn 0;")
        finding = finding_for(run, "ipc.relay.descriptor-boundary")
        self.assertIn(IMPACT_BY_RULE["ipc.relay.descriptor-boundary"], finding.message)
        self.assertNotIn("CWE-200", finding.message)

    def test_data01_out_of_bounds_read_is_reported_as_a_read_consequence(self):
        run = run_snippet(self.ENTRY % (
            "if (data.ReadInterfaceToken() != GetDescriptor()) return -1;\n"
            "char dst[64]; int n=data.ReadInt32(); memcpy(dst,data.ReadBuffer(64),n);\nreturn 0;"))
        finding = finding_for(run, "ipc.parcel.copy-range")
        self.assertIn("out_of_bounds_read", finding.message)
        self.assertIn("CWE-125", finding.message)
        self.assertEqual(finding.candidate_cwe, "CWE-20")

    def test_consequence_is_stated_as_unestablished(self):
        run = run_snippet(self.ENTRY % "return GetPasteData();")
        finding = finding_for(run, "ipc.auth.missing")
        self.assertIn("not established", finding.message)


class MachineReadableConsequenceTests(unittest.TestCase):
    """Contract v2 §3: the consequence is a field now, not only message text."""

    ENTRY = DetectorConsequenceTests.ENTRY

    def test_a_read_consequence_is_machine_readable_and_keeps_the_mechanism_cwe(self):
        run = run_snippet(self.ENTRY % "return GetPasteData();")
        finding = finding_for(run, "ipc.auth.missing")
        self.assertEqual(finding.consequence_impact, "information_disclosure")
        self.assertEqual(finding.consequence_cwe, "CWE-200")
        # The mechanism is a different answer and is not overwritten by it.
        self.assertEqual(finding.candidate_cwe, "CWE-862")

    def test_a_baseline_consequence_carries_no_cwe_the_catalogue_cannot_justify(self):
        run = run_snippet(self.ENTRY % "OnCallback();\nreturn 0;")
        finding = finding_for(run, "ipc.relay.descriptor-boundary")
        self.assertEqual(finding.consequence_impact, IMPACT_BY_RULE["ipc.relay.descriptor-boundary"])
        self.assertIsNone(finding.consequence_cwe)

    def test_the_catalogue_never_emits_its_own_unknown_sentinel(self):
        # `unknown` means "no modelled consequence"; it must leave as None so a
        # consumer cannot sort it as a classified category.
        run = run_snippet(self.ENTRY % "return GetPasteData();")
        for finding in run.findings:
            self.assertNotEqual(finding.consequence_impact, "unknown")
            if finding.consequence_impact is not None:
                self.assertIn(finding.consequence_impact, IMPACT_DESCRIPTION)


if __name__ == "__main__":
    unittest.main()
