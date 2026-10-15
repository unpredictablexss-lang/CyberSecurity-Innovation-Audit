import copy
import inspect
import unittest

from src.benchmark.tool_result import ToolRunResult
from src.ohscanner.contracts import Detector, DetectorRun, EvidenceObligation
from research.contracts.a_ccr_04.conformance import (
    CONTRACT,
    ContractViolation,
    METHODS,
    validate_response,
)


def proof():
    return [{
        "evidence_id": "evidence:source:fixture",
        "kind": "source_sha256",
        "authority": "source_blob",
        "object_sha256": "a" * 64,
        "verified": True,
    }]


def scope():
    return {
        "repository": "fixture/ohscanner-core",
        "commit": "b" * 40,
        "git_tree": "c" * 40,
        "snapshot_sha256": "d" * 64,
        "profile_id": "light-ast",
        "files": [{
            "path": "src/example.cpp",
            "blob": "e" * 40,
            "source_sha256": "a" * 64,
        }],
        "functions": ["example"],
        "detector": {"detector_id": "ohscanner.cpp.null", "version": "0.1.0"},
        "build_context_id": "build:fixture:1",
    }


def budget(exhausted=None, reason=None):
    limits = {
        "wall_time_ms": 1000,
        "memory_mb": 256,
        "files": 2,
        "source_bytes": 4096,
        "call_depth": 8,
        "cfg_nodes": 128,
        "paths": 16,
        "dataflow_steps": 32,
        "macro_rounds": 4,
    }
    used = dict(limits)
    used.update({
        "wall_time_ms": 1,
        "memory_mb": 1,
        "files": 1,
        "source_bytes": 1,
        "call_depth": 1,
        "cfg_nodes": 1,
        "paths": 1,
        "dataflow_steps": 1,
        "macro_rounds": 1,
    })
    return {
        "requested": limits,
        "used": used,
        "exhausted": list(exhausted or []),
        "reason": reason,
    }


def response(method, status="observed", facts=None, unknown=None, failure=None,
             response_budget=None):
    data = {
        "schema_version": CONTRACT["schema_version"],
        "change_request_id": "A-CCR-04",
        "method": method,
        "request_id": "req-a-ccr-04",
        "status": status,
        "proof_ref": proof() if status in ("observed", "proven") else [],
        "analysis_scope": scope(),
        "budget": response_budget or budget(),
        "failure_reason": failure,
        "facts": facts,
        "coverage": {
            "state": "complete",
            "analyzed_files": ["src/example.cpp"],
            "partial_files": [],
            "not_analyzed_files": [],
            "failed_files": [],
        },
        "limitations": ["proposal fixture only"],
        "unknown_reason": unknown,
    }
    return data


class ReadOnlyFactViewContractTests(unittest.TestCase):
    def test_contract_covers_all_required_methods(self):
        self.assertEqual(METHODS, (
            "get_symbol",
            "get_cfg_path",
            "get_dataflow",
            "get_guard_proof",
            "get_lock_state",
            "get_build_context",
            "get_source_context",
            "get_detector_results",
            "get_coverage",
        ))
        self.assertEqual(
            [item["name"] for item in CONTRACT["methods"]],
            list(METHODS),
        )

    def test_every_method_has_proof_scope_budget_and_failure_fields(self):
        required = set(CONTRACT["response_envelope"]["required_fields"])
        self.assertLessEqual({
            "proof_ref", "analysis_scope", "budget", "failure_reason"
        }, required)
        for method in CONTRACT["methods"]:
            self.assertIn("missing_behavior", method)
            self.assertIn("proof_required", method)
            self.assertIn("observed_fact", method)
            self.assertIn("proven_claim", method)
            method_name = method["name"]
            validate_response(method_name, response(method_name, facts={"fact": "bound"}))
            validate_response(method_name, response(method_name, status="unknown", facts=None, unknown={
                "code": "required_fact_missing",
                "message": "required semantic input is unavailable",
                "missing_facts": ["required semantic fact"],
            }))

    def test_observed_response_requires_bound_proof_and_facts(self):
        validate_response("get_symbol", response("get_symbol", facts={"symbol": "value"}))
        with self.assertRaises(ContractViolation):
            validate_response("get_symbol", response("get_symbol", facts=None))
        bad = response("get_symbol", facts={"symbol": "value"})
        bad["proof_ref"] = []
        with self.assertRaises(ContractViolation):
            validate_response("get_symbol", bad)

    def test_proven_response_requires_verified_proof(self):
        good = response("get_cfg_path", status="proven", facts={"path": ["n1", "n2"]})
        validate_response("get_cfg_path", good)
        bad = copy.deepcopy(good)
        bad["proof_ref"][0]["verified"] = False
        with self.assertRaises(ContractViolation):
            validate_response("get_cfg_path", bad)

    def test_missing_semantic_facts_return_unknown_without_guesses(self):
        cases = {
            "get_cfg_path": "required_fact_missing",
            "get_dataflow": "required_fact_missing",
            "get_guard_proof": "required_fact_missing",
            "get_lock_state": "required_fact_missing",
            "get_build_context": "build_context_unavailable",
        }
        for method, code in cases.items():
            with self.subTest(method=method):
                payload = response(method, status="unknown", facts=None, unknown={
                    "code": code,
                    "message": "required semantic input is unavailable",
                    "missing_facts": ["required semantic fact"],
                })
                validate_response(method, payload)

    def test_unknown_response_cannot_fabricate_semantic_path(self):
        payload = response("get_cfg_path", status="unknown", facts={
            "path": ["entry", "sink"]
        }, unknown={
            "code": "required_fact_missing",
            "message": "no CFG",
            "missing_facts": ["cfg"],
        })
        with self.assertRaises(ContractViolation):
            validate_response("get_cfg_path", payload)

    def test_failed_response_carries_failure_reason_and_no_facts(self):
        payload = response("get_source_context", status="failed", facts=None, failure={
            "code": "integrity_mismatch",
            "message": "source hash mismatch",
            "retryable": False,
        })
        validate_response("get_source_context", payload)
        payload["facts"] = {"text": "untrusted"}
        with self.assertRaises(ContractViolation):
            validate_response("get_source_context", payload)

    def test_v1_unbound_detector_record_is_observed_not_proven(self):
        facts = {
            "schema_version": 1,
            "diagnostic_id": "legacy-tool:diagnostic-1",
            "source_binding": "unbound",
            "candidate_status": "candidate",
        }
        payload = response("get_detector_results", facts=facts)
        validate_response("get_detector_results", payload)
        self.assertEqual(payload["facts"]["source_binding"], "unbound")
        self.assertEqual(payload["facts"]["candidate_status"], "candidate")

    def test_partial_coverage_is_preserved(self):
        facts = {
            "status": "partial",
            "complete": ["src/a.cpp"],
            "partial": ["src/b.cpp"],
            "not_analyzed": ["src/c.cpp"],
            "failed": ["src/d.cpp"],
        }
        payload = response("get_coverage", facts=facts)
        validate_response("get_coverage", payload)
        self.assertEqual(payload["facts"]["status"], "partial")
        self.assertEqual(payload["facts"]["not_analyzed"], ["src/c.cpp"])

    def test_existing_detector_schema_and_partial_coverage_remain_compatible(self):
        self.assertEqual(
            list(inspect.signature(Detector.detect).parameters),
            ["self", "context", "units"],
        )
        obligation = EvidenceObligation("guard_dominance", "prove guard")
        self.assertEqual(obligation.status, "unknown")
        run = DetectorRun(
            "ohscanner.cpp.null",
            "0.1.0",
            "blocked",
            analyzed_files=("src/example.cpp",),
            file_outcomes=(("src/example.cpp", "partial"),),
        )
        self.assertEqual(run.file_outcomes, (("src/example.cpp", "partial"),))
        for version in (1, 2):
            result = ToolRunResult(
                schema_version=version,
                run_id="run",
                tool="legacy-or-first-party",
                tool_version="1",
                target_id="target",
                commit="a" * 40,
                scope_files=1,
                scope_loc=1,
                status="blocked",
                elapsed_seconds=0.0,
            )
            self.assertEqual(result.schema_version, version)

    def test_evidence_obligations_are_read_only_in_contract(self):
        self.assertIn(
            "returned as immutable records",
            CONTRACT["compatibility"]["evidence_obligations"],
        )
        self.assertTrue(CONTRACT["public_implementation_changed"] is False)
        self.assertTrue(CONTRACT["approval_required"] is True)


if __name__ == "__main__":
    unittest.main()
