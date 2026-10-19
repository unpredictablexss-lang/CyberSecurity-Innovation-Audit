import unittest

from src.core.case import (
    VulnerabilityCase,
    make_case_id,
    make_evidence_id,
)
from src.core.evidence import Evidence


class CaseDataModelTests(unittest.TestCase):
    def test_evidence_to_dict_round_trips_fields(self) -> None:
        evidence = Evidence(
            evidence_id="evt-1",
            type="runtime",
            source="asan",
            location="cJSON_Utils.c:243",
            content="applying zero offset to null pointer",
            confidence=0.9,
        )
        data = evidence.to_dict()
        self.assertEqual(data["evidence_id"], "evt-1")
        self.assertEqual(data["type"], "runtime")
        self.assertEqual(data["location"], "cJSON_Utils.c:243")
        self.assertEqual(data["confidence"], 0.9)

    def test_case_to_dict_serializes_nested_evidence(self) -> None:
        evidence = Evidence(
            evidence_id="evt-1", type="runtime", source="tsan", content="data race"
        )
        case = VulnerabilityCase(
            case_id="case-1",
            title="DelayedSingleton UAF",
            root_cause="shared_ptr non-atomic read/write race",
            cwe="CWE-416",
            primary_location="singleton.h:GetInstance",
            evidence=[evidence],
        )
        data = case.to_dict()
        self.assertEqual(data["report_status"], "candidate")
        self.assertEqual(data["severity"], "unassessed")
        self.assertEqual(data["evidence"][0]["type"], "runtime")
        self.assertEqual(data["cwe"], "CWE-416")

    def test_make_case_id_is_stable_and_deterministic(self) -> None:
        first = make_case_id("t", "rc", "loc")
        second = make_case_id("t", "rc", "loc")
        other = make_case_id("t", "rc", "other")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other)
        self.assertEqual(len(first), 16)

    def test_make_evidence_id_differs_on_content(self) -> None:
        a = make_evidence_id("asan", "SEGV")
        b = make_evidence_id("asan", "SEGV")
        c = make_evidence_id("asan", "other")
        self.assertEqual(a, b)
        self.assertNotEqual(a, c)

    def test_case_defaults_keep_unassessed_boundaries(self) -> None:
        case = VulnerabilityCase(
            case_id="c", title="t", root_cause="r", cwe="CWE-120"
        )
        self.assertEqual(case.report_status, "candidate")
        self.assertEqual(case.confidence, "unassessed")
        self.assertEqual(case.patch_validation, "not_started")
        self.assertEqual(case.affected_versions, [])


if __name__ == "__main__":
    unittest.main()
