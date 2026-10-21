import copy
import hashlib
import unittest

from src.workbench.joint_candidate_comparison import (
    JointCandidateValidationError,
    JOINT_CANDIDATE_COMPARISON_SCHEMA,
    build_joint_candidate_context,
    unknown_joint_candidate_result,
    validate_joint_candidate_output,
    validate_joint_candidate_output_or_unknown,
)


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class JointCandidateFailureStateTests(unittest.TestCase):
    def test_preflight_provider_and_response_failures_do_not_look_completed(self):
        from src.workbench.joint_candidate_comparison import joint_comparison_failure_status

        self.assertEqual(joint_comparison_failure_status("not_started"), "blocked")
        self.assertEqual(joint_comparison_failure_status("attempted"), "failed")
        self.assertEqual(joint_comparison_failure_status("response_received"), "completed_with_limitations")


class JointCandidateComparisonTests(unittest.TestCase):
    def setUp(self):
        self.repo_id = "repo-fixed-id"
        self.from_commit = "a" * 40
        self.to_commit = "b" * 40
        self.from_tree = "c" * 40
        self.to_tree = "d" * 40
        self.from_blob = "e" * 40
        self.to_blob = "f" * 40
        self.from_text = "int old_guard = 0;\nif (!CheckPermission()) return;\nDoSensitive();\n"
        self.to_text = "int new_guard = 0;\nif (CheckPermission()) {\n    DoSensitive();\n}\n"
        self.from_source_sha = sha(self.from_text)
        self.to_source_sha = sha(self.to_text)
        self.from_candidate = {
            "id": "candidate-from", "file": "src/guard.cpp", "line": 2,
            "source_sha256": self.from_source_sha, "detector_id": "detector.guard",
            "detector_version": "1.2.3", "rule_id": "AUTH-01", "symbol": "Guard",
        }
        self.to_candidate = {
            "id": "candidate-to", "file": "src/guard.cpp", "line": 2,
            "source_sha256": self.to_source_sha, "detector_id": "detector.guard",
            "detector_version": "1.2.3", "rule_id": "AUTH-01", "symbol": "Guard",
        }
        self.from_side = self.make_side("from", self.from_commit, self.from_tree,
                                        self.from_blob, self.from_candidate,
                                        self.from_source_sha, self.from_text)
        self.to_side = self.make_side("to", self.to_commit, self.to_tree,
                                      self.to_blob, self.to_candidate,
                                      self.to_source_sha, self.to_text)
        self.match = {
            "status": "persistent_candidate", "match_basis": "detector_rule_path_symbol",
            "before": [{"id": "candidate-from", "source_sha256": self.from_source_sha,
                        "detector_version": "1.2.3"}],
            "after": [{"id": "candidate-to", "source_sha256": self.to_source_sha,
                       "detector_version": "1.2.3"}],
            "file": "src/guard.cpp", "detector_id": "detector.guard", "rule_id": "AUTH-01",
        }
        self.matrix_result = {
            "scan_ids": ["job-from", "job-to"],
            "versions": [
                {"commit": self.from_commit, "source_snapshot_sha256": "4" * 64},
                {"commit": self.to_commit, "source_snapshot_sha256": "5" * 64},
            ],
            "comparisons": [{
                "from": self.from_commit, "to": self.to_commit,
                "candidate_comparison": [copy.deepcopy(self.match)],
            }],
        }
        self.matrix_operation = {
            "id": "matrix-op-1", "kind": "version_matrix",
            "status": "completed_with_limitations",
            "spec": {"repository_id": self.repo_id},
            "result_sha256": "1" * 64,
        }
        self.prepared = self.prepare()

    def make_side(self, suffix, commit, tree, blob, candidate, source_sha, text):
        job = {
            "id": "job-" + suffix, "repository_id": self.repo_id,
            "status": "completed_with_limitations", "report_sha256": (("2" if suffix == "from" else "3") * 64),
            "spec": {"commit": commit, "git_tree": tree},
        }
        report = {
            "repository": "openharmony/lib",
            "commit": commit,
            "git_tree": tree,
            "snapshot_sha256": (("4" if suffix == "from" else "5") * 64),
            "_workbench": {"source_inventory": [{
                "file": candidate["file"], "sha256": source_sha, "blob": blob,
            }]},
        }
        source = {
            "file": candidate["file"], "commit": commit, "blob": blob,
            "sha256": source_sha, "text": text,
        }
        return {"job": job, "report": report, "candidate": candidate, "source": source}

    def prepare(self, **overrides):
        args = {
            "matrix_operation": self.matrix_operation,
            "matrix_result": self.matrix_result,
            "from_side": self.from_side,
            "to_side": self.to_side,
            "match": self.match,
        }
        args.update(overrides)
        return build_joint_candidate_context(**args)

    def candidate_output(self):
        return {
            "assessment": "candidate",
            "summary": "两侧固定源码在 guard 条件上有变化，仍需人工确认可达性与影响。",
            "introduced_or_fixed": "candidate_inference",
            "supported_claims": [{
                "claim": "from 与 to 的权限检查条件不同。",
                "citations": [
                    {"side": "from", "evidence_id": self.prepared["bindings"]["from"]["evidence_id"],
                     "file": "src/guard.cpp", "line_start": 2, "line_end": 2},
                    {"side": "to", "evidence_id": self.prepared["bindings"]["to"]["evidence_id"],
                     "file": "src/guard.cpp", "line_start": 2, "line_end": 2},
                ],
            }],
            "unknowns": ["调用方是否可控仍未知。"],
            "limitations": [],
        }

    def test_build_binds_both_fixed_endpoint_reports_and_sources(self):
        ctx = self.prepared
        self.assertEqual(ctx["bindings"]["matrix_operation_id"], "matrix-op-1")
        self.assertEqual(ctx["bindings"]["matrix_result_sha256"], "1" * 64)
        self.assertEqual(ctx["bindings"]["from"]["commit"], self.from_commit)
        self.assertEqual(ctx["bindings"]["to"]["commit"], self.to_commit)
        self.assertEqual(ctx["bindings"]["from"]["source_sha256"], self.from_source_sha)
        self.assertEqual(ctx["bindings"]["to"]["source_sha256"], self.to_source_sha)
        self.assertNotEqual(ctx["bindings"]["from"]["evidence_id"],
                            ctx["bindings"]["to"]["evidence_id"])
        self.assertEqual(set(ctx["evidence_index"]), {
            ctx["bindings"]["from"]["evidence_id"], ctx["bindings"]["to"]["evidence_id"],
        })
        self.assertEqual(ctx["context"]["from"]["source_excerpt_start_line"], 1)
        self.assertEqual(ctx["context"]["to"]["source_excerpt_end_line"], 4)

    def recent_window_inputs(self):
        windows = [
            {"baseline": "9" * 40, "endpoint": self.from_commit},
            {"baseline": self.from_commit, "endpoint": self.to_commit},
        ]
        scan_ids = ["old-baseline", "job-from", "new-baseline", "job-to"]
        operation = {
            "id": "f" * 32, "kind": "recent_window_comparison",
            "status": "completed_with_limitations",
            "spec": {"repository_id": self.repo_id, "windows": windows, "scan_ids": scan_ids},
            "result_sha256": "6" * 64,
        }
        result = {
            "scan_ids": list(scan_ids),
            "windows": [
                {"selection": dict(row), "baseline": row["baseline"], "endpoint": row["endpoint"]}
                for row in windows
            ],
            "between_window_endpoints": {
                "from": self.from_commit, "to": self.to_commit,
                "candidate_comparison": [copy.deepcopy(self.match)],
            },
        }
        return operation, result

    def test_recent_window_context_uses_only_fixed_between_window_endpoints(self):
        operation, result = self.recent_window_inputs()
        context = build_joint_candidate_context(
            source_operation=operation, source_result=result,
            source_result_sha256=operation["result_sha256"],
            from_side=self.from_side, to_side=self.to_side, match=self.match)
        self.assertEqual(context["bindings"]["source_operation_kind"], "recent_window_comparison")
        self.assertEqual(context["bindings"]["recent_window_operation_id"], operation["id"])
        self.assertEqual(context["bindings"]["recent_window_result_sha256"], "6" * 64)
        self.assertEqual(context["bindings"]["from"]["job_id"], "job-from")
        self.assertEqual(context["bindings"]["to"]["job_id"], "job-to")
        self.assertEqual({row["side"] for row in context["evidence_index"].values()}, {"from", "to"})
        self.assertNotIn("matrix_operation_id", context["bindings"])

    def test_recent_window_context_rejects_any_non_endpoint_scan_or_commit(self):
        operation, result = self.recent_window_inputs()
        bad_result = copy.deepcopy(result)
        bad_result["scan_ids"][1] = "other-job"
        with self.assertRaises(JointCandidateValidationError) as error:
            build_joint_candidate_context(
                source_operation=operation, source_result=bad_result,
                from_side=self.from_side, to_side=self.to_side, match=self.match)
        self.assertEqual(error.exception.reason_code, "recent_window_binding_mismatch")
        with self.assertRaises(JointCandidateValidationError) as error:
            build_joint_candidate_context(
                source_operation=operation, source_result=result,
                from_side=self.from_side, to_side=self.to_side, match=self.match,
                source_result_sha256="7" * 64)
        self.assertEqual(error.exception.reason_code, "parent_result_binding_mismatch")

    def test_valid_two_sided_citations_are_rebuilt_from_fixed_lines(self):
        result = validate_joint_candidate_output(self.candidate_output(), self.prepared)
        self.assertEqual(result["assessment"], "candidate")
        self.assertEqual(result["vulnerability_state"], "candidate")
        self.assertEqual(result["introduced_or_fixed"], "candidate_inference")
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertIsNone(result["poc"])
        citations = result["supported_claims"][0]["citations"]
        self.assertEqual([item["quote"] for item in citations],
                         ["if (!CheckPermission()) return;", "if (CheckPermission()) {"])
        self.assertEqual(result["bindings"], self.prepared["bindings"])

    def test_successful_result_discloses_citation_validation_is_not_semantic_validation(self):
        value = self.candidate_output()
        value["supported_claims"][0]["claim"] = "The guard conditions are identical."
        result = validate_joint_candidate_output(value, self.prepared)
        self.assertEqual(result["assessment"], "candidate")
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertTrue(any(
            "不验证引用语义是否支持模型主张" in limitation
            for limitation in result["limitations"]
        ))

    def test_unknown_result_can_have_no_claims_and_never_confirms_version_status(self):
        value = {
            "assessment": "unknown", "summary": "证据不足。",
            "introduced_or_fixed": "unknown", "supported_claims": [],
            "unknowns": ["动态可达性未知。"], "limitations": [],
        }
        result = validate_joint_candidate_output(value, self.prepared)
        self.assertEqual(result["assessment"], "unknown")
        self.assertEqual(result["introduced_or_fixed"], "unknown")
        self.assertEqual(result["validated_vulnerability"], 0)

    def assert_bad_output(self, mutate):
        value = self.candidate_output()
        mutate(value)
        with self.assertRaises(JointCandidateValidationError):
            validate_joint_candidate_output(value, self.prepared)

    def test_rejects_cross_side_evidence_id(self):
        def mutate(value):
            citation = value["supported_claims"][0]["citations"][0]
            citation["side"] = "to"
        self.assert_bad_output(mutate)

    def test_rejects_fabricated_evidence_id(self):
        def mutate(value):
            value["supported_claims"][0]["citations"][0]["evidence_id"] = "ev-joint-from-fabricated"
        self.assert_bad_output(mutate)

    def test_rejects_non_exact_file_and_path_traversal(self):
        def wrong_file(value):
            value["supported_claims"][0]["citations"][0]["file"] = "src/other.cpp"
        self.assert_bad_output(wrong_file)

        def traversal(value):
            value["supported_claims"][0]["citations"][0]["file"] = "../guard.cpp"
        self.assert_bad_output(traversal)

    def test_rejects_line_ranges_outside_indexed_excerpt_and_boolean_lines(self):
        def out_of_range(value):
            value["supported_claims"][0]["citations"][0]["line_start"] = 9
            value["supported_claims"][0]["citations"][0]["line_end"] = 9
        self.assert_bad_output(out_of_range)

        def boolean_line(value):
            value["supported_claims"][0]["citations"][0]["line_start"] = True
        self.assert_bad_output(boolean_line)

    def test_rejects_one_sided_claim_and_duplicate_citation(self):
        def one_side(value):
            value["supported_claims"][0]["citations"].pop()
        self.assert_bad_output(one_side)

        def duplicate(value):
            cites = value["supported_claims"][0]["citations"]
            cites.append(copy.deepcopy(cites[0]))
        self.assert_bad_output(duplicate)

    def test_rejects_confirmed_state_extra_field_and_duplicate_json_keys(self):
        def confirmed(value):
            value["assessment"] = "confirmed"
        self.assert_bad_output(confirmed)

        def extra(value):
            value["validated_vulnerability"] = 1
        self.assert_bad_output(extra)

        with self.assertRaises(JointCandidateValidationError):
            validate_joint_candidate_output(
                '{"assessment":"unknown","assessment":"candidate"}', self.prepared)

    def test_fail_closed_adapter_returns_unknown_for_invalid_output(self):
        result = validate_joint_candidate_output_or_unknown(
            {"assessment": "confirmed"}, self.prepared)
        self.assertEqual(result["assessment"], "unknown")
        self.assertEqual(result["vulnerability_state"], "unknown")
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertEqual(result["matrix_operation_id"], "matrix-op-1")

    def test_unknown_helper_never_accepts_arbitrary_reason_text(self):
        result = unknown_joint_candidate_result("../../secret", matrix_operation_id="matrix-op-1")
        self.assertEqual(result["failure_reason_code"], "analysis_unavailable")
        self.assertEqual(result["validated_vulnerability"], 0)

    def test_rejects_endpoint_from_another_repository(self):
        bad_side = copy.deepcopy(self.to_side)
        bad_side["job"]["repository_id"] = "different-repository"
        with self.assertRaises(JointCandidateValidationError) as error:
            self.prepare(to_side=bad_side)
        self.assertEqual(error.exception.reason_code, "repository_mismatch")

    def test_rejects_ambiguous_candidate_pair_and_duplicate_endpoint_pair(self):
        bad = copy.deepcopy(self.match)
        bad["before"].append(copy.deepcopy(bad["before"][0]))
        with self.assertRaises(JointCandidateValidationError) as error:
            self.prepare(match=bad)
        self.assertEqual(error.exception.reason_code, "ambiguous_candidate_pair")

        self.matrix_result["comparisons"].append(copy.deepcopy(self.matrix_result["comparisons"][0]))
        with self.assertRaises(JointCandidateValidationError) as error:
            self.prepare()
        self.assertEqual(error.exception.reason_code, "ambiguous_version_pair")

    def test_rejects_matrix_hash_source_hash_and_report_inventory_mismatch(self):
        with self.assertRaises(JointCandidateValidationError) as error:
            self.prepare(matrix_result_sha256="9" * 64)
        self.assertEqual(error.exception.reason_code, "matrix_result_binding_mismatch")

        bad_side = copy.deepcopy(self.to_side)
        bad_side["source"]["sha256"] = "9" * 64
        with self.assertRaises(JointCandidateValidationError) as error:
            self.prepare(to_side=bad_side)
        self.assertEqual(error.exception.reason_code, "source_binding_mismatch")

        bad_side = copy.deepcopy(self.from_side)
        bad_side["report"]["_workbench"]["source_inventory"] = []
        with self.assertRaises(JointCandidateValidationError) as error:
            self.prepare(from_side=bad_side)
        self.assertEqual(error.exception.reason_code, "source_binding_mismatch")

        bad_side = copy.deepcopy(self.to_side)
        bad_side["source"]["text"] = "tampered source text"
        with self.assertRaises(JointCandidateValidationError) as error:
            self.prepare(to_side=bad_side)
        self.assertEqual(error.exception.reason_code, "source_binding_mismatch")

    def test_rejects_endpoint_job_not_bound_to_matrix_scan_or_snapshot(self):
        bad_side = copy.deepcopy(self.to_side)
        bad_side["job"]["id"] = "unrelated-scan"
        with self.assertRaises(JointCandidateValidationError) as error:
            self.prepare(to_side=bad_side)
        self.assertEqual(error.exception.reason_code, "matrix_result_binding_mismatch")

        bad_side = copy.deepcopy(self.from_side)
        bad_side["report"]["snapshot_sha256"] = "9" * 64
        with self.assertRaises(JointCandidateValidationError) as error:
            self.prepare(from_side=bad_side)
        self.assertEqual(error.exception.reason_code, "matrix_result_binding_mismatch")

    def test_schema_forbids_unbounded_or_confirmed_product_fields(self):
        schema = JOINT_CANDIDATE_COMPARISON_SCHEMA
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["assessment"]["enum"], ["candidate", "unknown"])
        self.assertEqual(schema["properties"]["introduced_or_fixed"]["enum"],
                         ["unknown", "candidate_inference"])
        cite_schema = schema["properties"]["supported_claims"]["items"]["properties"]["citations"]["items"]
        self.assertFalse(cite_schema["additionalProperties"])
        self.assertIn("side", cite_schema["required"])


class JointCandidateComparisonRedactionTests(unittest.TestCase):
    def test_preview_redacts_model_bound_source_text_with_shared_policy(self):
        from src.workbench.joint_candidate_comparison_runtime import _redact_joint_context

        secret = "test_joint_secret_987654321"
        prepared = {
            "context": {"from": {"source_excerpt": 'api_key = "' + secret + '";'}},
            "evidence_index": {
                "ev-joint-from-test": {
                    "side": "from", "source_sha256": "a" * 64,
                    "lines": [{"line": 1, "text": 'api_key = "' + secret + '";'}],
                },
            },
        }
        redacted, categories = _redact_joint_context(prepared)
        serialized = __import__("json").dumps(redacted, ensure_ascii=False)

        self.assertNotIn(secret, serialized)
        self.assertIn("[REDACTED_SECRET]", serialized)
        self.assertIn("credential_assignment", categories)
        self.assertEqual(redacted["redaction_policy_version"],
                         __import__("src.workbench.agent", fromlist=["REDACTION_POLICY_VERSION"])
                         .REDACTION_POLICY_VERSION)
        self.assertEqual(redacted["evidence_index"]["ev-joint-from-test"]["source_sha256"],
                         "a" * 64)


if __name__ == "__main__":
    unittest.main()


class JointCandidateProviderCallStateTests(unittest.TestCase):
    def _execute_with_provider_outcome(self, provider_create, response_text):
        from types import SimpleNamespace
        from unittest.mock import MagicMock, patch
        from src.workbench import joint_candidate_comparison_runtime as runtime
        provider = SimpleNamespace(configured=True, fingerprint="a" * 64,
                                   endpoint_host="provider.example", model="offline",
                                   provider="fake")
        prepared = {
            "bindings": {"linked_agent_results": {"from": [], "to": []}},
            "context": {"matrix_match": {}},
            "evidence_index": {},
            "redaction_policy_version": "test-policy",
            "schema": {},
        }
        selectors = {
            "matrix_operation_id": "matrix-1",
            "from_commit": "1" * 40, "from_candidate_id": "candidate-a",
            "to_commit": "2" * 40, "to_candidate_id": "candidate-b",
        }
        spec = {
            **selectors,
            "source_submission_approved": True,
            "consent_nonce": "3" * 32,
            "consent_sha256": "4" * 64,
            "consent_expires_at": "2099-01-01T00:00:00+00:00",
            "provider_fingerprint": provider.fingerprint,
            "provider_host": provider.endpoint_host,
            "provider_model": provider.model,
            "joint_binding_snapshot": prepared["bindings"],
            "joint_context_sha256": "5" * 64,
            "provider_request_timeout_seconds": 45,
            "max_provider_retries": 0,
            "max_output_tokens": 3000,
        }
        task = {"id": "operation-1", "kind": "version_candidate_comparison", "spec": spec}
        ops = MagicMock()
        fake_client = MagicMock()
        fake_client.create.side_effect = provider_create
        with (
            patch("src.workbench.agent.ProviderConfig.from_env", return_value=provider),
            patch("src.workbench.agent.ResponsesClient", return_value=fake_client),
            patch.object(runtime, "prepare_joint_comparison", return_value=(prepared, selectors)),
            patch.object(runtime, "_redact_joint_context", return_value=(prepared, [])),
            patch.object(runtime, "canonical_sha256", return_value=spec["joint_context_sha256"]),
            patch.object(runtime, "_expires_at_is_valid", return_value=True),
            patch.object(runtime, "build_joint_consent_digest", return_value=spec["consent_sha256"]),
            patch("src.workbench.agent._response_text", side_effect=response_text),
        ):
            result = runtime.execute_joint_comparison(
                SimpleNamespace(data_dir="/tmp"), MagicMock(), ops, task)
        return result, fake_client

    def test_provider_timeout_is_not_reported_as_definitely_not_called(self):
        result, fake_client = self._execute_with_provider_outcome(
            TimeoutError("offline timeout"), RuntimeError("unused"))
        self.assertEqual(fake_client.create.call_count, 1)
        self.assertIsNone(result["model_called"])
        self.assertEqual(result["provider_call_state"], "outcome_unknown")
        self.assertIn("receipt or processing is unknown", result["limitations"][-1])

    def test_response_parse_failure_still_records_provider_response(self):
        response = {"status": "completed", "output": []}
        result, fake_client = self._execute_with_provider_outcome(
            response, RuntimeError("malformed output"))
        self.assertEqual(fake_client.create.call_count, 1)
        self.assertTrue(result["model_called"])
        self.assertEqual(result["provider_call_state"], "response_received")
