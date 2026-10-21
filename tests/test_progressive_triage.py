"""Focused contract tests for progressive triage policy and evidence ranking."""

import copy
import os
from pathlib import Path
import tempfile
import unittest

from src.workbench.progressive_triage import (
    PolicyStore,
    build_policy,
    group_candidates,
    rank_groups,
)
from src.workbench.progressive_triage.policy import (
    PolicyError,
    PolicyRevisionConflict,
    PolicyStoreError,
)
from src.workbench.progressive_triage.contracts import content_sha256
from src.workbench.progressive_triage.runtime import build_operation_plan


REPOSITORY = "open-harmony/example"
COMMIT = "a" * 40
SNAPSHOT = "b" * 64
SOURCE = "c" * 64


def bound_candidate(candidate_id, *, group=0, family="cpp_memory_safety", **extra):
    return {
        "candidate_id": candidate_id,
        "repository": REPOSITORY,
        "commit": COMMIT,
        "snapshot_sha256": SNAPSHOT,
        "source_sha256": SOURCE,
        "source_binding_verified": True,
        "detector_id": family,
        "detector_version": "1.0.0",
        "rule_id": "rule-" + family,
        "file": f"src/file_{group}.cpp",
        "line": 20 + group,
        "column": 3,
        "symbol": f"function_{group}",
        "cwe": "CWE-284",
        "status": "unassessed",
        **extra,
    }


class GroupingAndRankingTests(unittest.TestCase):
    def test_uncertain_same_path_and_cwe_stay_separate_and_unknown_is_not_selected(self):
        candidates = [
            {"candidate_id": "one", "file": "src/shared.cpp", "cwe": "CWE-284", "status": "unassessed"},
            {"candidate_id": "two", "file": "src/shared.cpp", "cwe": "CWE-284", "status": "unassessed"},
        ]
        manifest = group_candidates(candidates)
        self.assertEqual(manifest["group_count"], 2)
        self.assertTrue(all(group["grouping_confidence"] == "not_merged" for group in manifest["groups"]))
        ranked = rank_groups(manifest["groups"], 2)
        self.assertEqual(ranked["selected_group_count"], 0)
        self.assertTrue(all(row["coverage_unknown"] for row in ranked["decisions"]))
        self.assertEqual([item["status"] for item in candidates], ["unassessed", "unassessed"])

    def test_multiscan_runtime_freezes_policy_and_preserves_ranked_candidates(self):
        policy = build_policy("custom", {
            **build_policy()["limits"], "quick_screen_groups_per_audit": 1,
            "deep_groups_per_audit": 0, "max_model_calls_per_audit": 1,
        }, True)
        report = {"repository": REPOSITORY, "commit": COMMIT,
                  "snapshot_sha256": SNAPSHOT, "status": "completed"}
        findings = [
            {"id": "candidate-a", "detector_id": "cpp.memory", "detector_version": "1.0.0",
             "rule_id": "memory.rule", "file": "src/a.cpp", "line": 10,
             "source_sha256": SOURCE, "severity": "high", "status": "unassessed"},
            {"id": "candidate-b", "detector_id": "ipc.auth", "detector_version": "1.0.0",
             "rule_id": "ipc.rule", "file": "src/b.cpp", "line": 20,
             "source_sha256": "d" * 64, "severity": "medium", "status": "unassessed"},
        ]

        class FakeStore:
            def job(self, scan_id):
                return {"id": scan_id, "status": "completed", "report_sha256": "e" * 64}

        task = {"id": "audit-parent", "kind": "revision_range", "spec": {
            "scan_ids": ["scan-a"],
            "progressive_triage_policy": {"revision": 3, "policy": policy,
                                           "policy_sha256": content_sha256(policy)},
        }}
        result = build_operation_plan(
            object(), FakeStore(), task,
            read_report=lambda settings, job: report,
            findings=lambda value: findings,
            source_binding_valid=lambda value, candidate: True,
        )
        self.assertEqual(result["state"], "ranked_waiting_for_authorized_quick_screen")
        self.assertEqual(result["original_observation_count"], 2)
        self.assertEqual(result["ranking"]["selected_group_count"], 1)
        self.assertEqual(sum(1 for group in result["groups"] if group["state"] == "selected_for_quick_screen"), 1)
        self.assertTrue(all(group["quick_screen_state"] == "not_scheduled" for group in result["groups"]))
        self.assertEqual(result["validated_vulnerability"], 0)

    def test_root_cause_grouping_requires_deterministic_source_identity(self):
        identity = {
            "entry_id": "entry:1",
            "sink_id": "sink:2",
            "mechanism_id": "guard:missing",
            "relation_id": "flow:entry-to-sink",
            "source_fact_ids": ["fact:1", "fact:2"],
            "provenance": "deterministic_source_analysis",
        }
        candidates = [
            bound_candidate("one", group=1, root_cause_identity=identity),
            bound_candidate("one", group=1, root_cause_identity=identity),
            bound_candidate("two", group=2, root_cause_identity=identity),
        ]
        manifest = group_candidates(candidates)
        self.assertEqual(manifest["group_count"], 1)
        self.assertEqual(manifest["groups"][0]["group_kind"], "root_cause_candidate")
        self.assertEqual(manifest["groups"][0]["root_cause_conclusion"], "not_inferred")
        self.assertEqual(manifest["groups"][0]["exact_duplicate_group_count"], 2)
        self.assertEqual(manifest["groups"][0]["duplicate_observation_count"], 1)
        self.assertEqual(manifest["groups"][0]["observation_count"], 3)
        self.assertEqual(manifest["groups"][0]["grouping_confidence"], "same_deterministic_source_facts")

        exact = group_candidates([
            bound_candidate("same", group=3, root_cause_identity=identity),
            bound_candidate("same", group=3, root_cause_identity=identity),
        ])
        self.assertEqual(exact["groups"][0]["grouping_confidence"], "exact_fixed_source_observation")

        guessed = copy.deepcopy(candidates)
        for item in guessed:
            item["root_cause_identity"]["provenance"] = "model_summary"
        self.assertEqual(group_candidates(guessed)["group_count"], 2)

    def test_sha_shaped_fields_and_model_severity_do_not_substitute_for_verified_binding(self):
        candidate = bound_candidate("unverified", risk_assessment={"severity": "critical"})
        candidate.pop("source_binding_verified")
        group = group_candidates([candidate])["groups"][0]
        self.assertTrue(group["coverage_unknown"])
        ranked = rank_groups([group], 1)
        self.assertEqual(ranked["selected_group_count"], 0)
        self.assertEqual(ranked["decisions"][0]["score"], 0)

    def test_500_observations_keep_all_members_and_apply_budget_with_family_coverage(self):
        detector_families = (
            "ohscanner.cpp.shared_ptr_race",
            "ohscanner.interface.ipc",
            "ohscanner.javascript.typescript",
            "ohscanner.sensitive_data",
        )
        expected_families = {
            "cpp_memory_safety", "ipc_authorization", "script_api", "sensitive_data"
        }
        candidates = []
        for group in range(100):
            family = detector_families[group % len(detector_families)]
            prototype = bound_candidate(f"candidate-{group}", group=group, family=family)
            candidates.extend(copy.deepcopy(prototype) for _ in range(5))

        manifest = group_candidates(candidates)
        self.assertEqual(manifest["input_observation_count"], 500)
        self.assertEqual(manifest["group_count"], 100)
        self.assertEqual(sum(len(row["members"]) for row in manifest["groups"]), 500)

        # Ranking accepts generators and must still report retained member counts.
        result = rank_groups(iter(manifest["groups"]), 30, family_quotas=True)
        self.assertEqual(result["selected_group_count"], 30)
        self.assertEqual(result["retained_candidate_count"], 500)
        self.assertEqual(result["group_count"], 100)
        selected_families = {
            row["family_bucket"] for row in result["decisions"] if row["selected"]
        }
        self.assertEqual(selected_families, expected_families)
        self.assertEqual(
            sum(row["selected"] for row in result["decisions"]), 30
        )
        self.assertTrue(all(item["status"] == "unassessed" for item in candidates))

    def test_malformed_risk_assessment_does_not_crash_or_gain_score(self):
        candidate = bound_candidate("one", risk_assessment="untrusted shape")
        manifest = group_candidates([candidate])
        result = rank_groups(manifest["groups"], 1)
        self.assertEqual(result["selected_group_count"], 1)
        self.assertEqual(result["decisions"][0]["components"]["potential_impact"], 0)


class PolicyStoreTests(unittest.TestCase):
    def test_strict_policy_validation_and_atomic_revision_update(self):
        policy = build_policy()
        self.assertEqual(policy["profile"], "standard")
        with self.assertRaises(PolicyError):
            build_policy("custom", {**policy["limits"], "unexpected": 1}, True)
        with self.assertRaises(PolicyError):
            build_policy("custom", {**policy["limits"], "quick_screen_groups_per_audit": True}, True)

        with tempfile.TemporaryDirectory() as directory:
            store = PolicyStore(directory)
            initial = store.read()
            self.assertEqual(initial["revision"], 0)
            updated = store.update(build_policy("deep"), expected_revision=0)
            self.assertEqual(updated["revision"], 1)
            self.assertEqual(store.read()["policy"], build_policy("deep"))
            self.assertEqual(os.stat(Path(directory) / "progressive-triage-policy.json").st_mode & 0o777, 0o600)
            with self.assertRaises(PolicyRevisionConflict):
                store.update(build_policy("economical"), expected_revision=0)

    def test_policy_reader_rejects_symlinks_and_non_private_files(self):
        with tempfile.TemporaryDirectory() as directory:
            store = PolicyStore(directory)
            store.update(build_policy("deep"), expected_revision=0)
            target = Path(directory) / "policy-copy.json"
            target.write_bytes(store.path.read_bytes())
            store.path.unlink()
            store.path.symlink_to(target)
            with self.assertRaises(PolicyStoreError):
                store.read()

        with tempfile.TemporaryDirectory() as directory:
            store = PolicyStore(directory)
            store.update(build_policy("deep"), expected_revision=0)
            store.path.chmod(0o644)
            with self.assertRaises(PolicyStoreError):
                store.read()

    def test_dangling_symlink_is_not_treated_as_missing_default_policy(self):
        with tempfile.TemporaryDirectory() as directory:
            store = PolicyStore(directory)
            store.path.symlink_to(Path(directory) / "missing-policy-target")
            with self.assertRaises(PolicyStoreError):
                store.read()


try:
    from fastapi.testclient import TestClient
    from src.workbench.api import create_app
    from src.workbench.settings import Settings
except ModuleNotFoundError as error:
    if error.name.split(".")[0] not in {"fastapi", "httpx", "pydantic", "starlette"}:
        raise
    TestClient = None


@unittest.skipIf(TestClient is None, "optional workbench dependencies: install requirements-web.txt")
class PolicyApiTests(unittest.TestCase):
    def test_policy_digest_changes_the_frozen_consent_workflow(self):
        from src.workbench.operations_api import _progressive_workflow_sha256

        baseline = _progressive_workflow_sha256("a" * 64, "b" * 64)
        self.assertEqual(baseline, _progressive_workflow_sha256("a" * 64, "b" * 64))
        self.assertNotEqual(baseline, _progressive_workflow_sha256("a" * 64, "c" * 64))

    def test_policy_routes_reject_weak_requests_and_preserve_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory) / "data", ())
            with TestClient(create_app(settings)) as client:
                endpoint = "/api/v1/agent/triage-policy"
                current = client.get(endpoint)
                self.assertEqual(current.status_code, 200, current.text)
                self.assertEqual(current.json()["policy"]["profile"], "standard")
                self.assertEqual(current.json()["integration"]["worker_enforcement"], "not_connected")
                self.assertEqual(current.json()["integration"]["grouping_and_ranking"],
                                 "connected_to_multi_endpoint_operation_results")

                body = {"expected_revision": 0, "profile": "deep"}
                headers = {"x-ohscanner-client": "workbench-v1"}
                saved = client.put(endpoint, json=body, headers=headers)
                self.assertEqual(saved.status_code, 200, saved.text)
                self.assertEqual(saved.json()["revision"], 1)
                self.assertEqual(saved.json()["policy"]["profile"], "deep")

                stale = client.put(endpoint, json=body, headers=headers)
                self.assertEqual(stale.status_code, 409, stale.text)
                extra = client.put(endpoint, json={**body, "auto_confirm": True}, headers=headers)
                self.assertEqual(extra.status_code, 422, extra.text)
                limits = {**saved.json()["policy"]["limits"], "deep_groups_per_audit": 9999}
                invalid_limits = client.put(
                    endpoint,
                    json={"expected_revision": 1, "profile": "custom", "limits": limits},
                    headers=headers,
                )
                self.assertEqual(invalid_limits.status_code, 422, invalid_limits.text)
                missing_header = client.put(endpoint, json=body)
                self.assertEqual(missing_header.status_code, 403, missing_header.text)


if __name__ == "__main__":
    unittest.main()

class QuickScreenTests(unittest.TestCase):
    def setUp(self):
        from src.workbench.progressive_triage.quick_screen import run_quick_screen
        self.run = run_quick_screen
        self.group = {
            "group_id": "ptg-example",
            "family_bucket": "cpp_memory_safety",
            "members": [{"candidate_id": "candidate-1"}],
            "evidence_gaps": ["length_origin"],
        }
        self.provider_fingerprint = "provider-fingerprint-v1"
        self.model = "small-model"
        self.authorization = {
            "authorized": True,
            "audit_mode": "intelligent",
            "consent_sha256": "d" * 64,
            "report_sha256": SNAPSHOT,
            "commit": COMMIT,
            "repository": REPOSITORY,
            "provider_fingerprint": self.provider_fingerprint,
            "model": self.model,
            "redaction_policy_version": "ohscanner-egress-redaction-0.2.8",
        }
        import hashlib
        excerpt = "memcpy(dst, src, len);"
        self.evidence = [{
            "evidence_id": "source-1",
            "repository": REPOSITORY,
            "commit": COMMIT,
            "report_sha256": SNAPSHOT,
            "file": "src/example.cpp",
            "line_start": 10,
            "line_end": 14,
            "source_sha256": SOURCE,
            "excerpt_sha256": hashlib.sha256(excerpt.encode()).hexdigest(),
            "source_binding_verified": True,
            "redaction_applied": True,
            "redaction_policy_version": "ohscanner-egress-redaction-0.2.8",
            "sensitive_redactions": [],
            "text": excerpt,
        }]
        self.answer = {
            "group_id": "ptg-example",
            "quick_assessment": "investigate",
            "rationale": "Length origin is unresolved in the supplied excerpt.",
            "evidence_citations": ["source-1"],
            "missing_obligations": ["length_origin"],
            "next_tool_hints": ["find_callers"],
            "uncertainties": ["caller reachability is unknown"],
            "review_status": "model_unverified",
        }

    def response(self, answer=None):
        import json
        return {
            "status": "completed",
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": json.dumps(answer or self.answer)}],
            }],
            "usage": {"input_tokens": 700, "output_tokens": 120},
        }

    def test_static_mode_makes_no_provider_request(self):
        class NeverCall:
            called = False
            def create(self, *args, **kwargs):
                self.called = True
                raise AssertionError("static-only must not send")

        provider = NeverCall()
        authorization = {**self.authorization, "audit_mode": "static_only"}
        result = self.run(provider, self.group, self.evidence, authorization,
                          provider_fingerprint=self.provider_fingerprint, model=self.model)
        self.assertFalse(provider.called)
        self.assertEqual(result["state"], "quick_unknown")
        self.assertEqual(result["validated_vulnerability"], 0)

    def test_success_uses_one_no_tools_bounded_request_and_keeps_candidate_status(self):
        class Provider:
            def __init__(self, response):
                self.response = response
                self.calls = []
            def create(self, payload, **kwargs):
                self.calls.append((payload, kwargs))
                return self.response

        provider = Provider(self.response())
        result = self.run(provider, self.group, self.evidence, self.authorization,
                          provider_fingerprint=self.provider_fingerprint, model=self.model)
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["vulnerability_state"], "candidate")
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertEqual(result["usage"]["input_tokens"], 700)
        self.assertEqual(len(provider.calls), 1)
        payload, kwargs = provider.calls[0]
        self.assertNotIn("tools", payload)
        self.assertEqual(payload["max_output_tokens"], 512)
        self.assertEqual(kwargs, {"timeout": 90, "max_retries": 0})
        self.assertEqual(result["consent_sha256"], self.authorization["consent_sha256"])

    def test_invalid_citation_and_missing_usage_degrade_to_unknown(self):
        class Provider:
            def __init__(self, response):
                self.response = response
                self.called = False
            def create(self, *args, **kwargs):
                self.called = True
                return self.response

        invalid = dict(self.answer, evidence_citations=["invented-id"])
        provider = Provider(self.response(invalid))
        result = self.run(provider, self.group, self.evidence, self.authorization,
                          provider_fingerprint=self.provider_fingerprint, model=self.model)
        self.assertEqual(result["state"], "quick_unknown")
        self.assertEqual(result["reason_code"], "quick_screen_citation_invalid")
        self.assertEqual(result["validated_vulnerability"], 0)

        response = self.response()
        response.pop("usage")
        provider = Provider(response)
        result = self.run(provider, self.group, self.evidence, self.authorization,
                          provider_fingerprint=self.provider_fingerprint, model=self.model)
        self.assertEqual(result["state"], "quick_unknown")
        self.assertEqual(result["reason_code"], "provider_usage_missing_or_invalid")

    def test_provider_error_is_unknown_and_source_scope_expansion_is_rejected(self):
        class Provider:
            def __init__(self):
                self.calls = 0
            def create(self, *args, **kwargs):
                self.calls += 1
                raise TimeoutError("request outcome may be unknown")

        provider = Provider()
        result = self.run(provider, self.group, self.evidence, self.authorization,
                          provider_fingerprint=self.provider_fingerprint, model=self.model)
        self.assertEqual(result["state"], "quick_unknown")
        self.assertEqual(result["reason_code"], "provider_error_unknown_outcome")

        outside = [dict(self.evidence[0], file="../outside.cpp")]
        result = self.run(provider, self.group, outside, self.authorization,
                          provider_fingerprint=self.provider_fingerprint, model=self.model)
        self.assertEqual(result["state"], "quick_unknown")
        self.assertEqual(result["reason_code"], "evidence path is outside the fixed repository scope")
        self.assertEqual(provider.calls, 1)


class BudgetLedgerTests(unittest.TestCase):
    def setUp(self):
        from src.workbench.progressive_triage.contracts import content_sha256
        from src.workbench.progressive_triage.ledger import BudgetLedger
        self.BudgetLedger = BudgetLedger
        self.policy = build_policy()
        self.sha = content_sha256(self.policy)

    def create(self, directory, policy=None):
        from src.workbench.progressive_triage.contracts import content_sha256
        policy = policy or self.policy
        return self.BudgetLedger(Path(directory) / "triage-budget.sqlite"), policy, content_sha256(policy)

    def test_task_wide_atomic_reservations_and_unknown_provider_outcome(self):
        import threading
        from src.workbench.progressive_triage.ledger import BudgetError
        with tempfile.TemporaryDirectory() as directory:
            policy = build_policy("custom", {
                **build_policy()["limits"],
                "max_model_concurrency": 1,
            }, True)
            ledger, policy, sha = self.create(directory, policy)
            ledger.create_audit("audit-1", policy, sha)
            for group_id in ("group-1", "group-2"):
                ledger.dispatch_group("audit-1", group_id, "endpoint-" + group_id,
                                      "quick_screen", evidence_gate="ranked_and_selected")
            results = []
            def reserve(group_id):
                try:
                    results.append(ledger.reserve(
                        "audit-1", "key-" + group_id, "endpoint-" + group_id, group_id,
                        "quick_screen", max_input_tokens=1000, max_output_tokens=512,
                    ))
                except Exception as error:
                    results.append(error)
            threads = [threading.Thread(target=reserve, args=(group_id,))
                       for group_id in ("group-1", "group-2")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()
            self.assertEqual(sum(isinstance(item, dict) for item in results), 1)
            self.assertEqual(sum(isinstance(item, BudgetError) for item in results), 1)
            reservation = next(item for item in results if isinstance(item, dict))
            replay = ledger.reserve(
                reservation["audit_id"], "key-" + reservation["group_id"],
                reservation["endpoint_id"], reservation["group_id"], "quick_screen",
                max_input_tokens=1000, max_output_tokens=512,
            )
            self.assertTrue(replay["idempotent_replay"])
            ledger.settle(reservation["reservation_id"], outcome="unknown_outcome")
            snapshot = ledger.get("audit-1")
            self.assertEqual(snapshot["usage"]["input_tokens_allocated"], 1000)
            self.assertEqual(snapshot["usage"]["output_tokens_allocated"], 512)
            self.assertEqual(snapshot["usage"]["model_calls_allocated"], 1)
            self.assertEqual(snapshot["cost"]["actual_usd"], None)
            self.assertEqual(snapshot["cost"]["enforcement"], "advisory_only")

    def test_deep_agent_requires_completed_investigate_and_policy_sha_is_immutable(self):
        from src.workbench.progressive_triage.ledger import BudgetError, BudgetConflict
        with tempfile.TemporaryDirectory() as directory:
            ledger, policy, sha = self.create(directory)
            ledger.create_audit("audit-2", policy, sha)
            with self.assertRaises(BudgetConflict):
                ledger.create_audit("audit-2", build_policy("deep"),
                                    __import__("src.workbench.progressive_triage.contracts", fromlist=["content_sha256"]).content_sha256(build_policy("deep")))
            ledger.dispatch_group("audit-2", "group-1", "endpoint-1",
                                  "quick_screen", evidence_gate="ranked_and_selected")
            with self.assertRaises(BudgetError):
                ledger.dispatch_group("audit-2", "group-1", "endpoint-1",
                                      "deep_agent", evidence_gate="quick_screen_investigate")
            quick = ledger.reserve(
                "audit-2", "quick-1", "endpoint-1", "group-1", "quick_screen",
                max_input_tokens=1000, max_output_tokens=512,
            )
            ledger.settle(quick["reservation_id"], outcome="completed",
                          input_tokens=500, output_tokens=100, quick_assessment="investigate")
            deep = ledger.dispatch_group("audit-2", "group-1", "endpoint-1",
                                         "deep_agent", evidence_gate="quick_screen_investigate")
            self.assertEqual(deep["status"], "queued")
            self.assertEqual(ledger.get("audit-2")["phase_counts"]["deep_agent_groups"], 1)

    def test_strict_cost_fails_closed_without_provider_cap_and_known_not_sent_releases(self):
        from src.workbench.progressive_triage.ledger import BudgetError
        with tempfile.TemporaryDirectory() as directory:
            ledger, policy, sha = self.create(directory)
            with self.assertRaises(BudgetError):
                ledger.create_audit("audit-3", policy, sha, strict_cost=True)
            ledger.create_audit("audit-3", policy, sha)
            ledger.dispatch_group("audit-3", "group-1", "endpoint-1",
                                  "quick_screen", evidence_gate="ranked_and_selected")
            reservation = ledger.reserve(
                "audit-3", "unsent", "endpoint-1", "group-1", "quick_screen",
                max_input_tokens=1000, max_output_tokens=512,
            )
            ledger.settle(reservation["reservation_id"], outcome="known_not_sent")
            usage = ledger.get("audit-3")["usage"]
            self.assertEqual(usage["model_calls_allocated"], 0)
            self.assertEqual(usage["input_tokens_allocated"], 0)


    def test_budget_ledger_rejects_symlink_database_and_non_private_directory(self):
        from src.workbench.progressive_triage.ledger import BudgetLedger
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.sqlite"
            target.write_bytes(b"")
            link = Path(directory) / "ledger.sqlite"
            link.symlink_to(target)
            with self.assertRaises(OSError):
                BudgetLedger(link)

        with tempfile.TemporaryDirectory() as directory:
            Path(directory).chmod(0o755)
            with self.assertRaises(ValueError):
                BudgetLedger(Path(directory) / "ledger.sqlite")
