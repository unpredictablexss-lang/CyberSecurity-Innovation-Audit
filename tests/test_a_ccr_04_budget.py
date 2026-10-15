import copy
import unittest

from research.contracts.a_ccr_04.conformance import (
    ContractViolation,
    validate_budget_payload,
    validate_response,
)
from tests.test_a_ccr_04_contract import budget, response


def unknown_budget_response(method, exhausted_field):
    return response(
        method,
        status="unknown",
        facts=None,
        response_budget=budget(
            exhausted=[exhausted_field],
            reason=f"{exhausted_field} limit reached",
        ),
        unknown={
            "code": "budget_exhausted",
            "message": "finite analysis budget exhausted",
            "missing_facts": [exhausted_field],
        },
    )


class ReadOnlyFactViewBudgetTests(unittest.TestCase):
    def test_all_budget_limits_are_required_and_positive(self):
        data = budget()
        data["requested"]["paths"] = 0
        with self.assertRaises(ContractViolation):
            validate_budget_payload(data)

    def test_used_budget_cannot_exceed_requested_budget(self):
        data = budget()
        data["used"]["dataflow_steps"] = data["requested"]["dataflow_steps"] + 1
        with self.assertRaises(ContractViolation):
            validate_budget_payload(data)

    def test_missing_budget_is_rejected(self):
        with self.assertRaises(ContractViolation):
            validate_budget_payload({"requested": {}, "used": {}, "exhausted": []})

    def test_cfg_path_budget_exhaustion_is_unknown_not_a_partial_path(self):
        payload = unknown_budget_response("get_cfg_path", "paths")
        validate_response("get_cfg_path", payload)
        self.assertIsNone(payload["facts"])
        self.assertEqual(payload["unknown_reason"]["code"], "budget_exhausted")
        self.assertEqual(payload["budget"]["exhausted"], ["paths"])

    def test_dataflow_budget_exhaustion_is_unknown_not_a_partial_flow(self):
        payload = unknown_budget_response("get_dataflow", "dataflow_steps")
        validate_response("get_dataflow", payload)
        self.assertIsNone(payload["facts"])
        self.assertEqual(payload["unknown_reason"]["code"], "budget_exhausted")
        self.assertEqual(payload["budget"]["exhausted"], ["dataflow_steps"])

    def test_source_context_budget_exhaustion_is_unknown_not_truncated_text(self):
        payload = unknown_budget_response("get_source_context", "source_bytes")
        validate_response("get_source_context", payload)
        self.assertIsNone(payload["facts"])
        self.assertEqual(payload["unknown_reason"]["code"], "budget_exhausted")

    def test_budget_exhaustion_must_be_unknown(self):
        payload = unknown_budget_response("get_dataflow", "call_depth")
        payload["status"] = "observed"
        payload["facts"] = {"flow": ["source", "sink"]}
        payload["unknown_reason"] = None
        with self.assertRaises(ContractViolation):
            validate_response("get_dataflow", payload)

    def test_budget_exhaustion_reason_code_is_fixed(self):
        payload = unknown_budget_response("get_guard_proof", "cfg_nodes")
        payload["unknown_reason"]["code"] = "analysis_partial"
        with self.assertRaises(ContractViolation):
            validate_response("get_guard_proof", payload)

    def test_invalid_budget_is_failed_not_unknown(self):
        invalid = budget()
        invalid["requested"]["wall_time_ms"] = 0
        payload = response(
            "get_symbol",
            status="failed",
            facts=None,
            response_budget=invalid,
            failure={
                "code": "invalid_budget",
                "message": "requested wall_time_ms must be positive",
                "retryable": False,
            },
        )
        validate_response("get_symbol", payload)
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(payload["failure_reason"]["code"], "invalid_budget")
        self.assertIsNone(payload["facts"])

        observed = response(
            "get_symbol",
            status="observed",
            facts={"symbol": "value"},
            response_budget=invalid,
        )
        with self.assertRaises(ContractViolation):
            validate_response("get_symbol", observed)

    def test_response_budget_usage_is_mandatory(self):
        payload = response("get_lock_state", facts={"state": "observed"})
        del payload["budget"]
        with self.assertRaises(ContractViolation):
            validate_response("get_lock_state", payload)

    def test_budget_test_fixture_is_finite_and_measured(self):
        data = budget()
        self.assertEqual(
            set(data["requested"]),
            set(data["used"]),
        )
        for field, value in data["requested"].items():
            self.assertGreater(value, 0, field)
            self.assertLessEqual(data["used"][field], value, field)


if __name__ == "__main__":
    unittest.main()
