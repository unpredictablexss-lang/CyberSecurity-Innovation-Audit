import json
import unittest
from src.workbench import agent
from src.workbench.agent_output import check_output_contract, output_contract_prompt, OutputValidationError

class OutputContractTests(unittest.TestCase):
    def test_missing_keys_are_exact_and_arbitrary_values_not_retained(self):
        with self.assertRaises(OutputValidationError) as caught:
            agent._validate_final('{"secret-key-123":"secret-value-456"}', {})
        diagnostic = agent.safe_validation_diagnostic(caught.exception, "invalid_schema", "primary")
        self.assertEqual(diagnostic["issues"][0]["missing"], agent._FINAL_SCHEMA["required"])
        self.assertEqual(diagnostic["issues"][0]["unexpected_field_count"], 1)
        self.assertNotIn("secret-", json.dumps(diagnostic))

    def test_wrong_disposition_points_to_exact_review(self):
        value = agent._rejected_structured_answer(2)
        value["obligation_reviews"][1]["disposition"] = "unknown"
        with self.assertRaises(OutputValidationError) as caught:
            agent._validate_final(json.dumps(value), {}, [{}, {}])
        self.assertEqual(agent._validation_error_code(caught.exception), "invalid_obligation_review")
        self.assertEqual(caught.exception.issues[0]["path"], "$.obligation_reviews[1].disposition")
        self.assertEqual(caught.exception.issues[0]["allowed"], ["evidence_found", "contrary_evidence", "unresolved"])

    def test_primary_template_has_every_obligation_and_passes_real_validator(self):
        prompt = output_contract_prompt(agent._FINAL_SCHEMA, 6)
        self.assertIn('"obligation_index":5', prompt)
        value = agent._rejected_structured_answer(6)
        self.assertEqual(agent._validate_final(json.dumps(value), {}, [{}]*6)["assessment"], "unknown")

    def test_skeptic_schema_uses_independent_enum(self):
        prompt = output_contract_prompt(agent._SKEPTIC_SCHEMA, 6, skeptic=True)
        self.assertIn('"obligation_index":5', prompt)
        value = {"reviews": [{"obligation_index": i, "result": "unknown", "citations": []} for i in range(6)]}
        self.assertEqual(len(agent._validate_skeptic_review(json.dumps(value), [{}]*6, [], {})), 6)
        value["reviews"][0]["result"] = "unresolved"
        with self.assertRaises(OutputValidationError) as caught:
            agent._validate_skeptic_review(json.dumps(value), [{}]*6, [], {})
        self.assertEqual(agent._skeptic_validation_error_code(caught.exception), "skeptic_invalid_review")
        self.assertEqual(caught.exception.issues[0]["path"], "$.reviews[0].result")

    def test_skeptic_extra_fields_rejected_without_exposing_model_text(self):
        value = {"reviews": [{"obligation_index": 0, "result": "unknown", "citations": [], "secret": "sensitive"}]}
        with self.assertRaises(OutputValidationError) as caught:
            agent._validate_skeptic_review(json.dumps(value), [{}], [], {})
        self.assertNotIn("sensitive", json.dumps(caught.exception.issues))

    def test_skeptic_citation_policy_remains_strict(self):
        value = {"reviews": [{"obligation_index": 0, "result": "no_counterevidence_observed", "citations": [{"evidence_id":"e1", "file":"a.cpp", "line_start":1, "line_end":1}]}]}
        with self.assertRaises(ValueError) as caught:
            agent._validate_skeptic_review(json.dumps(value), [{}], [0], {})
        self.assertEqual(agent._skeptic_validation_error_code(caught.exception), "skeptic_unexpected_citation")

    def test_first_correction_gets_specific_schema_and_review_feedback(self):
        self.assertIn("Top-level fields", agent._structured_repair_prompt([0], 1, previous_error_code="invalid_schema"))
        self.assertIn("disposition", agent._structured_repair_prompt([0], 1, previous_error_code="invalid_obligation_review"))

    def test_context_overflow_is_reported_as_context_failure(self):
        self.assertEqual(agent._repair_budget_error_code(ValueError("Provider request exceeds the per-request input byte limit")), "per_request_context_limit")

    def test_source_reference_options_pass_the_actual_citation_validator(self):
        lines = {"e1": {"a.cpp": {i: "int value = 1;" for i in range(1, 23)}}}
        options = agent.source_citation_options(lines)
        self.assertGreater(len(options), 1)
        for citation in options:
            value = {"reviews": [{"obligation_index": 0, "result": "counterevidence_candidate", "citations": [citation]}]}
            self.assertEqual(len(agent._validate_skeptic_review(json.dumps(value), [{}], [0], lines)), 1)

    def test_source_options_exclude_too_long_or_unavailable_lines(self):
        options = agent.source_citation_options({"e1": {"a.cpp": {1:"x"*501, 3:"int good = 1;"}}})
        self.assertEqual(options, [{"evidence_id":"e1", "file":"a.cpp", "line_start":3, "line_end":3}])
