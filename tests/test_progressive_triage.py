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


class ProgressiveStatusTests(unittest.TestCase):
    def test_snapshot_status_uses_frozen_scan_policy_and_read_only_report(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from src.workbench.progressive_triage.status import build_progressive_status

        policy = build_policy()
        frozen = {"revision": 2, "policy": policy,
                  "policy_sha256": content_sha256(policy)}
        report = {"repository": REPOSITORY, "commit": COMMIT,
                  "snapshot_sha256": SNAPSHOT, "status": "completed"}
        candidates = [{"id": "candidate-snapshot", "detector_id": "cpp.memory",
                       "detector_version": "1.0.0", "rule_id": "memory.rule",
                       "file": "src/a.cpp", "line": 12, "source_sha256": SOURCE,
                       "severity": "high", "status": "unassessed"}]

        class FakeStore:
            def job(self, key):
                return {"id": key, "status": "completed", "report_sha256": "e" * 64,
                        "spec": {"audit_mode": "standard_review",
                                 "progressive_triage_policy": frozen}}

        class FakeOperations:
            def get(self, _key):
                raise KeyError("operation not found")

            def progressive_operations_for_audit(self, _key):
                return []

        with tempfile.TemporaryDirectory() as directory, \
                patch("src.workbench.service.read_report", return_value=report), \
                patch("src.workbench.service.findings", return_value=candidates), \
                patch("src.workbench.smart_audit._source_binding_valid", return_value=True):
            status = build_progressive_status(SimpleNamespace(data_dir=Path(directory)),
                                              FakeOperations(), "snapshot-1", store=FakeStore())
        self.assertEqual(status["phase"], "awaiting_quick_screen_authorization")
        self.assertEqual(status["phase_counts"]["candidate_count"], 1)
        self.assertEqual(status["groups"][0]["members"][0]["candidate_id"], "candidate-snapshot")
        self.assertEqual(status["validated_vulnerability"], 0)

    def test_status_projects_plan_and_child_operations_without_changing_findings(self):
        from types import SimpleNamespace
        from src.workbench.progressive_triage.status import build_progressive_status

        policy = build_policy()
        frozen = {"revision": 7, "policy": policy,
                  "policy_sha256": content_sha256(policy)}
        plan = {
            "state": "ranked_waiting_for_authorized_quick_screen",
            "policy_revision": 7, "policy_sha256": frozen["policy_sha256"],
            "original_observation_count": 2,
            "ranking": {"decisions": [{"group_id": "g1", "selected": True}]},
            "groups": [{"group_id": "g1", "members": [
                {"candidate_id": "c1"}, {"candidate_id": "c2"}],
                "ranking": {"selected": True}, "state": "selected_for_quick_screen"}],
            "validated_vulnerability": 0,
        }
        audit = {"id": "audit-1", "kind": "revision_range", "status": "completed",
                 "result_sha256": "r" * 64,
                 "spec": {"progressive_triage_policy": frozen}}
        quick = {"id": "quick-1", "kind": "progressive_quick_screen", "status": "running",
                 "created_at": "2026-10-22T01:00:00Z",
                 "spec": {"audit_operation_id": "audit-1", "group": {"group_id": "g1"}}}

        class FakeOperations:
            def get(self, key):
                self.asserted_key = key
                return audit

            def result(self, key):
                return {"progressive_triage": plan}

            def progressive_operations_for_audit(self, key):
                return [quick]

        with tempfile.TemporaryDirectory() as directory:
            status = build_progressive_status(SimpleNamespace(data_dir=Path(directory)),
                                              FakeOperations(), "audit-1")
        self.assertEqual(status["phase"], "quick_screening")
        self.assertEqual(status["phase_counts"]["candidate_count"], 2)
        self.assertEqual(status["phase_counts"]["unassessed_group_members"], 2)
        self.assertEqual(status["groups"][0]["quick_screen_state"], "running")
        self.assertIsNone(status["budget"])
        self.assertFalse(status["candidate_disposition_changed"])
        self.assertEqual(status["validated_vulnerability"], 0)
        self.assertEqual(plan["groups"][0]["members"], [{"candidate_id": "c1"}, {"candidate_id": "c2"}])

    def test_task_usage_and_group_routes_are_read_only_and_paginated(self):
        from unittest.mock import patch
        from src.workbench.api import create_app
        from src.workbench.settings import Settings
        from fastapi.testclient import TestClient

        policy = build_policy()
        frozen = {"revision": 1, "policy": policy,
                  "policy_sha256": content_sha256(policy)}
        audit = {"id": "audit-2", "kind": "version_matrix", "status": "completed",
                 "result_sha256": "r" * 64, "spec": {"progressive_triage_policy": frozen}}
        plan = {"state": "ranked_waiting_for_authorized_quick_screen",
                "original_observation_count": 2,
                "ranking": {"decisions": [{"group_id": "g1", "selected": True},
                                            {"group_id": "g2", "selected": False}]},
                "groups": [{"group_id": "g1", "members": [{"candidate_id": "c1"}]},
                           {"group_id": "g2", "members": [{"candidate_id": "c2"}]}]}
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(Settings(Path(directory) / "data", ()))
            with patch("src.workbench.operations_store.Operations.get", return_value=audit), \
                    patch("src.workbench.operations_store.Operations.result",
                          return_value={"progressive_triage": plan}), \
                    patch("src.workbench.operations_store.Operations.progressive_operations_for_audit",
                          return_value=[]):
                with TestClient(app) as client:
                    usage = client.get("/api/v1/audits/audit-2/ai-usage")
                    groups = client.get("/api/v1/audits/audit-2/triage-groups?offset=1&limit=1")
                    invalid = client.get("/api/v1/audits/audit-2/triage-groups?limit=201")
        self.assertEqual(usage.status_code, 200, usage.text)
        self.assertEqual(usage.json()["phase_counts"]["candidate_count"], 2)
        self.assertFalse(usage.json()["candidate_disposition_changed"])
        self.assertEqual(groups.status_code, 200, groups.text)
        self.assertEqual(groups.json()["group_total"], 2)
        self.assertEqual([row["group_id"] for row in groups.json()["groups"]], ["g2"])
        self.assertEqual(invalid.status_code, 422)


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

    def test_single_snapshot_runtime_marks_static_only_and_keeps_candidates(self):
        policy = build_policy()
        report = {"repository": REPOSITORY, "commit": COMMIT,
                  "snapshot_sha256": SNAPSHOT, "status": "completed"}
        findings = [{"id": "candidate-a", "detector_id": "cpp.memory",
                     "detector_version": "1.0.0", "rule_id": "memory.rule",
                     "file": "src/a.cpp", "line": 10, "source_sha256": SOURCE,
                     "severity": "high", "status": "unassessed"}]

        class FakeStore:
            def job(self, scan_id):
                return {"id": scan_id, "status": "completed", "report_sha256": "e" * 64}

        task = {"id": "scan-a", "kind": "snapshot", "spec": {
            "scan_ids": ["scan-a"], "audit_mode": "static_only",
            "progressive_triage_policy": {"revision": 2, "policy": policy,
                                           "policy_sha256": content_sha256(policy)},
        }}
        result = build_operation_plan(
            object(), FakeStore(), task,
            read_report=lambda settings, job: report,
            findings=lambda value: findings,
            source_binding_valid=lambda value, candidate: True,
        )
        self.assertEqual(result["state"], "ranked_static_only")
        self.assertEqual(result["original_observation_count"], 1)
        self.assertEqual(result["ranking"]["selected_group_count"], 1)
        self.assertTrue(any("no model request is permitted" in value
                            for value in result["limitations"]))
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertFalse(result["candidate_disposition_changed"])

    def test_limited_snapshot_keeps_observations_unknown_and_unselected(self):
        policy = build_policy()
        report = {"repository": REPOSITORY, "commit": COMMIT,
                  "snapshot_sha256": SNAPSHOT, "status": "completed"}
        findings = [{"id": "candidate-limited", "detector_id": "cpp.memory",
                     "rule_id": "memory.rule", "file": "src/a.cpp", "line": 10,
                     "source_sha256": SOURCE, "severity": "high"}]

        class FakeStore:
            def job(self, scan_id):
                return {"id": scan_id, "status": "completed_with_limitations",
                        "report_sha256": "e" * 64}

        task = {"id": "scan-limited", "kind": "snapshot", "spec": {
            "scan_ids": ["scan-limited"], "audit_mode": "standard_review",
            "progressive_triage_policy": {"revision": 0, "policy": policy,
                                           "policy_sha256": content_sha256(policy)},
        }}
        result = build_operation_plan(
            object(), FakeStore(), task,
            read_report=lambda settings, job: report,
            findings=lambda value: findings,
            source_binding_valid=lambda value, candidate: True,
        )
        self.assertEqual(result["state"], "partial_unknown")
        self.assertEqual(result["original_observation_count"], 1)
        self.assertEqual(result["ranking"]["selected_group_count"], 0)
        self.assertTrue(result["groups"][0]["ranking"]["coverage_unknown"])
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
    def test_progressive_policy_digest_is_bound_to_audit_workflow_hash(self):
        from src.workbench.service import audit_workflow_sha256

        base = audit_workflow_sha256("a" * 64, "standard_review")
        first = audit_workflow_sha256("a" * 64, "standard_review",
                                      progressive_policy_sha256="b" * 64)
        second = audit_workflow_sha256("a" * 64, "standard_review",
                                       progressive_policy_sha256="c" * 64)
        self.assertNotEqual(base, first)
        self.assertNotEqual(first, second)
        with self.assertRaises(ValueError):
            audit_workflow_sha256("a" * 64, "standard_review",
                                  progressive_policy_sha256="invalid")

    def test_snapshot_triage_route_returns_bounded_static_only_l0_l1_plan(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from src.workbench.progressive_triage.policy import policy_envelope

        policy = build_policy()
        frozen = {"revision": 4, "policy": policy,
                  "policy_sha256": policy_envelope(policy)["policy_sha256"]}
        job = {"id": "scan-a", "status": "completed", "report_sha256": "e" * 64,
               "spec": {"audit_mode": "static_only",
                        "progressive_triage_policy": frozen}}
        report = {"repository": REPOSITORY, "commit": COMMIT,
                  "snapshot_sha256": SNAPSHOT, "status": "completed"}
        candidates = [{"id": "candidate-a", "detector_id": "cpp.memory",
                       "detector_version": "1.0.0", "rule_id": "memory.rule",
                       "file": "src/a.cpp", "line": 10, "source_sha256": SOURCE,
                       "severity": "high", "status": "unassessed"}]

        with tempfile.TemporaryDirectory() as directory:
            app = create_app(Settings(Path(directory) / "data", ()))
            app.state.store.job = lambda key: job
            with patch("src.workbench.service.read_report", return_value=report), \
                    patch("src.workbench.service.findings", return_value=candidates), \
                    patch("src.workbench.smart_audit._source_binding_valid", return_value=True):
                with TestClient(app) as client:
                    response = client.get("/api/v1/scans/scan-a/progressive-triage?offset=0&limit=1")
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["state"], "ranked_static_only")
        self.assertEqual(body["group_total"], 1)
        self.assertEqual(len(body["groups"]), 1)
        self.assertEqual(body["validated_vulnerability"], 0)

    def test_endpoint_in_multi_endpoint_audit_defers_to_parent_budget_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(Settings(Path(directory) / "data", ()))
            app.state.store.job = lambda key: {
                "id": key, "status": "completed", "report_sha256": "e" * 64,
                "spec": {"audit_mode": "standard_review",
                         "progressive_triage_policy": {"revision": 0}},
            }
            app.state.operations.audit_parent_for_scan = lambda key: {"id": "parent-operation"}
            with TestClient(app) as client:
                response = client.get("/api/v1/scans/scan-a/progressive-triage")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["state"], "planned_by_parent_operation")
        self.assertEqual(response.json()["parent_operation_id"], "parent-operation")

    def test_policy_digest_changes_the_frozen_consent_workflow(self):
        from src.workbench.operations_api import _progressive_workflow_sha256

        baseline = _progressive_workflow_sha256("a" * 64, "b" * 64)
        self.assertEqual(baseline, _progressive_workflow_sha256("a" * 64, "b" * 64))
        self.assertNotEqual(baseline, _progressive_workflow_sha256("a" * 64, "c" * 64))

    def test_quick_screen_start_without_explicit_consent_makes_no_provider_call(self):
        from unittest.mock import patch
        from types import SimpleNamespace

        class Provider(SimpleNamespace):
            calls = 0

            def create(self, *args, **kwargs):
                self.calls += 1
                raise AssertionError("no consent means no Provider request")

        provider = Provider(configured=True)
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory) / "data", ())
            with patch("src.workbench.agent.ProviderConfig.from_env", return_value=provider):
                with TestClient(create_app(settings)) as client:
                    response = client.post("/api/v1/operations/progressive-quick-screens", headers={
                        "x-ohscanner-client": "workbench-v1"}, json={
                            "job_id": "a" * 32, "candidate_id": "candidate-1",
                            "source_submission_approved": False,
                        })
        self.assertEqual(response.status_code, 428, response.text)
        self.assertEqual(provider.calls, 0)

    def test_quick_screen_preview_start_persists_one_idempotent_operation(self):
        from datetime import datetime, timedelta, timezone
        from unittest.mock import patch
        from types import SimpleNamespace

        from src.workbench.progressive_triage.contracts import content_sha256
        from src.workbench.progressive_triage.policy import policy_envelope

        provider = SimpleNamespace(configured=True, fingerprint="f" * 64,
                                   model="screen-model", public={"model": "screen-model"})

        def prepare(_settings, _store, job_id, candidate_id, active_provider, nonce, expiry=None,
                    audit_parent=None, audit_parent_plan=None):
            expiry = expiry or (datetime.now(timezone.utc) + timedelta(minutes=8)).isoformat()
            policy = build_policy()
            policy_sha256 = policy_envelope(policy)["policy_sha256"]
            progressive_policy = {"revision": 0, "policy": policy,
                                  "policy_sha256": policy_sha256}
            group = {"group_id": "g1", "members": [{"candidate_id": candidate_id}]}
            evidence = [{"evidence_id": "e1", "text": "fixed excerpt"}]
            ranking = {"decisions": [{"group_id": "g1", "selected": True}]}
            manifest = {"consent_nonce": nonce, "consent_expires_at": expiry,
                        "audit_operation_id": job_id,
                        "group": group, "evidence": evidence,
                        "policy_revision": 0, "policy": policy,
                        "policy_sha256": policy_sha256, "ranking": ranking}
            digest = content_sha256(manifest)
            return {"eligible": True, "consent_nonce": nonce, "consent_expires_at": expiry,
                    "consent_sha256": digest, "consent_manifest": manifest,
                    "group": group, "evidence": evidence,
                    "progressive_policy": progressive_policy, "ranking": ranking,
                    "audit_operation_id": job_id,
                    "authorization": {"authorized": True, "consent_sha256": digest},
                    "provider": active_provider.public,
                    "disclosure": {"tools_enabled": False}}

        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory) / "data", ())
            with patch("src.workbench.agent.ProviderConfig.from_env", return_value=provider):
                with patch("src.workbench.progressive_triage.quick_screen_operation.prepare_quick_screen",
                           side_effect=prepare):
                    with TestClient(create_app(settings)) as client:
                        headers = {"x-ohscanner-client": "workbench-v1"}
                        preview = client.post("/api/v1/operations/progressive-quick-screens/preview",
                            headers=headers, json={"job_id": "a" * 32,
                                                  "candidate_id": "candidate-1"})
                        self.assertEqual(preview.status_code, 200, preview.text)
                        body = preview.json()
                        start_body = {"job_id": "a" * 32, "candidate_id": "candidate-1",
                                      "source_submission_approved": True,
                                      "consent_nonce": body["consent_nonce"],
                                      "consent_sha256": body["consent_sha256"],
                                      "consent_expires_at": body["consent_expires_at"]}
                        started = client.post("/api/v1/operations/progressive-quick-screens",
                                              headers=headers, json=start_body)
                        self.assertEqual(started.status_code, 201, started.text)
                        replay = client.post("/api/v1/operations/progressive-quick-screens",
                                             headers=headers, json=start_body)
                        self.assertEqual(replay.status_code, 201, replay.text)
        self.assertEqual(started.json()["id"], replay.json()["id"])
        self.assertEqual(started.json()["kind"], "progressive_quick_screen")
        self.assertEqual(started.json()["status"], "queued")

    def test_policy_routes_reject_weak_requests_and_preserve_revision(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory) / "data", ())
            with TestClient(create_app(settings)) as client:
                endpoint = "/api/v1/agent/triage-policy"
                current = client.get(endpoint)
                self.assertEqual(current.status_code, 200, current.text)
                self.assertEqual(current.json()["policy"]["profile"], "standard")
                self.assertEqual(current.json()["integration"]["worker_enforcement"],
                                 "l2_l3_fixed_source_consent_and_parent_budget_gate")
                self.assertEqual(current.json()["integration"]["quick_screen_executor"],
                             "task_level_explicit_consent_batch_and_individual_explicit_consent")
                self.assertEqual(current.json()["integration"]["task_budget_ledger"],
                                 "shared_across_fixed_endpoints_for_l2_and_l3")
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

    def test_incomplete_response_keeps_known_usage_and_explicit_truncation_reason(self):
        from types import SimpleNamespace
        response = self.response()
        response["status"] = "incomplete"
        response["incomplete_details"] = {"reason": "max_output_tokens", "untrusted_text": "private-secret"}
        response["usage"] = {"input_tokens": 1000, "output_tokens": 512}
        provider = SimpleNamespace(create=lambda *_args, **_kwargs: response)
        result = self.run(provider, self.group, self.evidence, self.authorization,
                          provider_fingerprint=self.provider_fingerprint, model=self.model)
        self.assertEqual(result["state"], "quick_unknown")
        self.assertEqual(result["failure"]["incomplete_reason"], "max_output_tokens")
        self.assertEqual(result["usage"]["output_tokens"], 512)
        self.assertNotIn("private-secret", str(result))

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
        self.assertEqual(result["reason_code"], "provider_timeout")
        self.assertEqual(result["failure"]["error_type"], "TimeoutError")
        self.assertEqual(result["failure"]["request_outcome"], "unknown")

        outside = [dict(self.evidence[0], file="../outside.cpp")]
        result = self.run(provider, self.group, outside, self.authorization,
                          provider_fingerprint=self.provider_fingerprint, model=self.model)
        self.assertEqual(result["state"], "quick_unknown")
        self.assertEqual(result["reason_code"], "evidence path is outside the fixed repository scope")
        self.assertEqual(provider.calls, 1)


class QuickScreenOperationTests(unittest.TestCase):
    def test_snapshot_preview_reuses_frozen_l0_l1_plan_and_static_only_is_rejected(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from src.workbench.progressive_triage.quick_screen_operation import prepare_quick_screen
        from src.workbench.progressive_triage.policy import policy_envelope

        policy = build_policy()
        frozen = {"revision": 3, "policy": policy,
                  "policy_sha256": policy_envelope(policy)["policy_sha256"]}
        job = {"id": "job-snapshot", "status": "completed", "report_sha256": "f" * 64,
               "spec": {"audit_mode": "standard_review",
                        "progressive_triage_policy": frozen}}
        report = {"repository": REPOSITORY, "commit": COMMIT,
                  "snapshot_sha256": SNAPSHOT, "status": "completed"}
        candidate = {"id": "candidate-snapshot", "file": "src/example.cpp", "line": 50,
                     "source_sha256": SOURCE, "detector_id": "cpp.memory",
                     "detector_version": "1.0.0", "rule_id": "memory.rule",
                     "severity": "high", "evidence": {}}
        prepared = {"source": {"text": "\n".join(f"line {i}" for i in range(1, 101))},
                    "initial_context": {"evidence_obligations": []},
                    "initial_evidence_id": "unused", "redaction_categories": []}
        provider = SimpleNamespace(fingerprint="provider-v1", model="small-model",
                                   public={"model": "small-model"})
        fake_store = SimpleNamespace(job=lambda _: job)
        settings = SimpleNamespace(data_dir="unused")
        common_patches = (
            patch("src.workbench.service.read_report", return_value=report),
            patch("src.workbench.service.finding", return_value=candidate),
            patch("src.workbench.service.findings", return_value=[candidate]),
            patch("src.workbench.smart_audit._source_binding_valid", return_value=True),
            patch("src.workbench.agent._prepare_candidate_context", return_value=prepared),
        )
        with (common_patches[0], common_patches[1], common_patches[2],
              common_patches[3], common_patches[4]):
            preview = prepare_quick_screen(settings, fake_store, "job-snapshot",
                                           "candidate-snapshot", provider, "a" * 32)
            self.assertTrue(preview["ranking"]["decisions"][0]["selected"])
            self.assertEqual(preview["consent_manifest"]["audit_parent_plan_sha256"],
                             preview["ranking"]["plan_sha256"])
            job["spec"]["audit_mode"] = "static_only"
            with self.assertRaisesRegex(ValueError, "static-only"):
                prepare_quick_screen(settings, fake_store, "job-snapshot",
                                     "candidate-snapshot", provider, "b" * 32)

    def test_preview_excerpt_is_redacted_and_within_fixed_line_and_byte_bounds(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from src.workbench.progressive_triage.quick_screen_operation import prepare_quick_screen

        with tempfile.TemporaryDirectory() as directory:
            data_dir = Path(directory) / "data"
            data_dir.mkdir(mode=0o700)
            settings = SimpleNamespace(data_dir=data_dir)
            source_lines = [f"int statement_{index};" for index in range(100)]
            source_lines[49] = "Authorization: Bearer test-secret-value"
            source_text = "\n".join(source_lines)
            job = {"id": "job-1", "status": "completed", "report_sha256": "f" * 64}
            report = {"repository": REPOSITORY, "commit": COMMIT,
                      "snapshot_sha256": SNAPSHOT, "status": "completed"}
            candidate = {"id": "candidate-1", "file": "src/example.cpp", "line": 50,
                         "source_sha256": SOURCE, "detector_id": "cpp.memory",
                         "rule_id": "memory.rule", "severity": "high", "evidence": {}}
            prepared = {"source": {"text": source_text}, "initial_context": {
                "evidence_obligations": [{"description": "check length origin"}]},
                "initial_evidence_id": "unused", "redaction_categories": []}
            provider = SimpleNamespace(fingerprint="provider-v1", model="small-model",
                                       public={"model": "small-model"})
            with patch("src.workbench.service.read_report", return_value=report), \
                    patch("src.workbench.service.finding", return_value=candidate), \
                    patch("src.workbench.smart_audit._source_binding_valid", return_value=True), \
                    patch("src.workbench.agent._prepare_candidate_context", return_value=prepared):
                preview = prepare_quick_screen(settings, SimpleNamespace(job=lambda _: job),
                                               "job-1", "candidate-1", provider, "a" * 32)
            evidence = preview["evidence"][0]
            self.assertLessEqual(evidence["line_end"] - evidence["line_start"], 39)
            self.assertLessEqual(len(evidence["text"].encode("utf-8")), 8_192)
            self.assertEqual(evidence["source_sha256"], SOURCE)
            self.assertNotIn("test-secret-value", evidence["text"])
            self.assertTrue(evidence["sensitive_redactions"])
            self.assertTrue(preview["ranking"]["decisions"][0]["selected"])
            self.assertEqual(preview["consent_sha256"], content_sha256(preview["consent_manifest"]))

    def test_multi_endpoint_preview_uses_parent_frozen_selection_and_group(self):
        from datetime import datetime, timedelta, timezone
        from types import SimpleNamespace
        from unittest.mock import patch
        from src.workbench.progressive_triage.quick_screen_operation import prepare_quick_screen
        from src.workbench.progressive_triage.ranking import rank_groups
        from src.workbench.progressive_triage.policy import policy_envelope
        from src.workbench.progressive_triage.contracts import content_sha256

        fixture = QuickScreenTests()
        fixture.setUp()
        policy = build_policy()
        policy_sha = policy_envelope(policy)["policy_sha256"]
        envelope = {"revision": 4, "policy": policy, "policy_sha256": policy_sha}
        endpoint_member = {"candidate_id": "candidate-1", "repository": REPOSITORY,
                           "commit": COMMIT, "report_sha256": "f" * 64,
                           "snapshot_sha256": SNAPSHOT, "source_sha256": SOURCE,
                           "source_binding_verified": True, "file": "src/example.cpp",
                           "line": 50, "coverage_status": "completed", "severity": "high"}
        parent_group = {"group_id": "root-cause-group-7", "members": [endpoint_member],
                        "evidence_gaps": ["inspect caller"]}
        ranking = rank_groups([parent_group], policy["limits"]["quick_screen_groups_per_audit"],
                              family_quotas=policy["family_quotas"])
        parent_plan = {"groups": [{**parent_group, "ranking": ranking["decisions"][0]}],
                       "ranking": ranking}
        parent = {"id": "b" * 32, "status": "completed", "cancel_requested": False,
                  "spec": {"scan_ids": ["job-1"], "audit_mode": "standard_review",
                           "progressive_triage_policy": envelope}}
        job = {"id": "job-1", "status": "completed", "report_sha256": "f" * 64}
        report = {"repository": REPOSITORY, "commit": COMMIT,
                  "snapshot_sha256": SNAPSHOT, "status": "completed"}
        candidate = {"id": "candidate-1", "file": "src/example.cpp", "line": 50,
                     "source_sha256": SOURCE, "detector_id": "cpp.memory",
                     "rule_id": "memory.rule", "severity": "high", "evidence": {}}
        prepared = {"source": {"text": "\n".join(f"line {i}" for i in range(1, 101))},
                    "initial_context": {"evidence_obligations": []},
                    "initial_evidence_id": "unused", "redaction_categories": []}
        provider = SimpleNamespace(fingerprint="provider-v1", model="small-model",
                                   public={"model": "small-model"})
        with patch("src.workbench.service.read_report", return_value=report), \
                patch("src.workbench.service.finding", return_value=candidate), \
                patch("src.workbench.smart_audit._source_binding_valid", return_value=True), \
                patch("src.workbench.agent._prepare_candidate_context", return_value=prepared):
            preview = prepare_quick_screen(SimpleNamespace(data_dir="unused"),
                                           SimpleNamespace(job=lambda _: job), "job-1",
                                           "candidate-1", provider, "c" * 32,
                                           audit_parent=parent, audit_parent_plan=parent_plan)
        self.assertEqual(preview["audit_operation_id"], parent["id"])
        self.assertEqual(preview["group"]["group_id"], "root-cause-group-7")
        self.assertEqual(preview["ranking"]["decisions"][0]["group_id"], "root-cause-group-7")
        self.assertEqual(preview["consent_manifest"]["audit_parent_plan_sha256"],
                         content_sha256(parent_plan))

    def _task(self):
        from datetime import datetime, timedelta, timezone
        from src.workbench.progressive_triage.quick_screen_operation import PROMPT_VERSION, QUICK_SCREEN_VERSION
        from src.workbench.progressive_triage.policy import policy_envelope
        from src.workbench.progressive_triage.ranking import rank_groups

        fixture = QuickScreenTests()
        fixture.setUp()
        policy = build_policy()
        policy_sha256 = policy_envelope(policy)["policy_sha256"]
        group = {**fixture.group, "members": [{
            **fixture.group["members"][0], "repository": REPOSITORY, "commit": COMMIT,
            "snapshot_sha256": SNAPSHOT, "source_sha256": SOURCE,
            "source_binding_verified": True, "file": "src/example.cpp",
        }]}
        ranking = rank_groups([group], policy["limits"]["quick_screen_groups_per_audit"],
                              family_quotas=policy["family_quotas"])
        expires = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
        manifest = {
            "consent_nonce": "e" * 32,
            "consent_expires_at": expires,
            "audit_operation_id": "job-1",
            "quick_screen_version": QUICK_SCREEN_VERSION,
            "prompt_version": PROMPT_VERSION,
            "group": group,
            "evidence": fixture.evidence,
            "fixed_source": {key: fixture.authorization[key] for key in
                             ("repository", "commit", "report_sha256")},
            "provider_fingerprint": fixture.provider_fingerprint,
            "model": fixture.model,
            "redaction_policy_version": fixture.authorization["redaction_policy_version"],
            "policy_revision": 0,
            "policy": policy,
            "policy_sha256": policy_sha256,
            "ranking": ranking,
        }
        digest = content_sha256(manifest)
        authorization = {**fixture.authorization, "consent_sha256": digest}
        spec = {
            "source_submission_approved": True,
            "consent_nonce": "e" * 32,
            "consent_sha256": digest,
            "consent_expires_at": expires,
            "audit_operation_id": "job-1",
            "consent_manifest": manifest,
            "group": group,
            "evidence": fixture.evidence,
            "authorization": authorization,
            "job_id": "job-1",
            "progressive_policy": {"revision": 0, "policy": policy,
                                   "policy_sha256": policy_sha256},
            "ranking": ranking,
        }
        return fixture, {"kind": "progressive_quick_screen", "spec": spec}

    def test_default_config_is_converted_to_transport_client_before_sending(self):
        import json
        from types import SimpleNamespace
        from unittest.mock import patch
        from src.workbench.agent import ProviderConfig
        from src.workbench.progressive_triage.quick_screen_operation import execute_quick_screen

        fixture, task = self._task()
        config = ProviderConfig("https://api.xiaomimimo.com/v1", fixture.model, "private-test-key")
        spec = task["spec"]
        spec["consent_manifest"]["provider_fingerprint"] = config.fingerprint
        digest = content_sha256(spec["consent_manifest"])
        spec["consent_sha256"] = digest
        spec["authorization"] = {**spec["authorization"], "provider_fingerprint": config.fingerprint,
                                 "consent_sha256": digest}
        calls = []
        class Response:
            status = 200
            def __enter__(self): return self
            def __exit__(self, *_): return False
            def read(self, _limit): return json.dumps(fixture.response()).encode()
        class Opener:
            def open(self, request, timeout=None):
                calls.append((request.full_url, json.loads(request.data)))
                return Response()
        with tempfile.TemporaryDirectory() as directory, \
                patch("src.workbench.agent.ProviderConfig.from_env", return_value=config), \
                patch("src.workbench.agent.build_opener", return_value=Opener()):
            result = execute_quick_screen(SimpleNamespace(data_dir=Path(directory)), task)
        self.assertEqual(result["state"], "completed", result)
        self.assertEqual(result["quick_screen"]["usage"]["input_tokens"], 700)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "https://api.xiaomimimo.com/v1/responses")
        self.assertEqual(calls[0][1]["reasoning"], {"effort": "none"})
        self.assertEqual(calls[0][1]["text"]["format"]["type"], "json_object")
        self.assertNotIn("tools", calls[0][1])
        self.assertEqual(result["validated_vulnerability"], 0)

    def test_failed_call_needs_fresh_consent_and_does_not_replay_automatically(self):
        import copy
        from types import SimpleNamespace
        from src.workbench.progressive_triage.quick_screen_operation import execute_quick_screen
        fixture, task = self._task()
        class Provider:
            configured = True
            fingerprint = fixture.provider_fingerprint
            model = fixture.model
            calls = 0
            def create(self, *_args, **_kwargs):
                self.calls += 1
                if self.calls == 1:
                    raise TimeoutError("unknown upstream outcome")
                return fixture.response()
        provider = Provider()
        with tempfile.TemporaryDirectory() as directory:
            settings = SimpleNamespace(data_dir=Path(directory))
            first = execute_quick_screen(settings, task, provider)
            repeated = execute_quick_screen(settings, task, provider)
            self.assertEqual(first["quick_screen"]["reason_code"], "provider_timeout")
            self.assertEqual(repeated["reason_code"], "prior_request_outcome_not_replayed")
            self.assertEqual(provider.calls, 1)
            fresh = copy.deepcopy(task)
            fresh["spec"]["consent_manifest"]["consent_nonce"] = "f" * 32
            fresh["spec"]["consent_nonce"] = "f" * 32
            digest = content_sha256(fresh["spec"]["consent_manifest"])
            fresh["spec"]["consent_sha256"] = digest
            fresh["spec"]["authorization"]["consent_sha256"] = digest
            retry = execute_quick_screen(settings, fresh, provider)
            self.assertEqual(retry["state"], "completed", retry)
            self.assertEqual(provider.calls, 2)
            self.assertEqual(retry["budget"]["usage"]["model_calls_allocated"], 2)

    def test_operation_rechecks_exact_consent_and_executes_no_tools_once(self):
        from src.workbench.progressive_triage.quick_screen_operation import execute_quick_screen
        from types import SimpleNamespace

        fixture, task = self._task()

        class Provider:
            configured = True
            fingerprint = fixture.provider_fingerprint
            model = fixture.model

            def __init__(self):
                self.calls = []

            def create(self, payload, **kwargs):
                self.calls.append((payload, kwargs))
                return fixture.response()

        provider = Provider()
        with tempfile.TemporaryDirectory() as directory:
            settings = SimpleNamespace(data_dir=Path(directory))
            result = execute_quick_screen(settings, task, provider)
            replay_provider = Provider()
            replay = execute_quick_screen(settings, task, replay_provider)
        self.assertEqual(result["state"], "completed")
        self.assertEqual(result["vulnerability_state"], "candidate")
        self.assertEqual(result["validated_vulnerability"], 0)
        self.assertEqual(result["quick_screen"]["usage"]["input_tokens"], 700)
        self.assertEqual(len(provider.calls), 1)
        self.assertEqual(result["budget"]["usage"]["model_calls_allocated"], 1)
        self.assertEqual(result["budget"]["usage"]["input_tokens_allocated"], 700)
        self.assertEqual(result["budget"]["usage"]["output_tokens_allocated"], 120)
        self.assertEqual(result["budget"]["cost"]["enforcement"], "advisory_only")
        self.assertEqual(replay["reason_code"], "prior_request_outcome_not_replayed")
        self.assertEqual(replay_provider.calls, [])
        payload, kwargs = provider.calls[0]
        self.assertNotIn("tools", payload)
        self.assertEqual(kwargs, {"timeout": 90, "max_retries": 0})

    def test_parent_plan_binding_execution_and_revocation(self):
        from types import SimpleNamespace
        from src.workbench.progressive_triage.quick_screen_operation import execute_quick_screen
        fixture, task = self._task()
        spec = task["spec"]
        spec["candidate_id"] = "candidate-1"
        spec["group"]["members"][0]["report_sha256"] = spec["authorization"]["report_sha256"]
        spec["audit_operation_id"] = "parent-audit"
        plan = {"groups": [spec["group"]], "ranking": spec["ranking"]}
        parent = {"id": "parent-audit", "spec": {
            "scan_ids": [spec["job_id"]],
            "progressive_triage_policy": spec["progressive_policy"]}}
        manifest = spec["consent_manifest"]
        manifest["audit_operation_id"] = "parent-audit"
        manifest["audit_parent_plan_sha256"] = content_sha256(plan)
        manifest["ranking"] = {"decisions": [plan["ranking"]["decisions"][0]], "plan_sha256": content_sha256(plan)}
        spec["consent_sha256"] = content_sha256(manifest)
        spec["authorization"]["consent_sha256"] = spec["consent_sha256"]
        ops = SimpleNamespace(get=lambda _: parent,
                              result=lambda _: {"progressive_triage": plan})
        calls = []
        provider = SimpleNamespace(configured=True, fingerprint=fixture.provider_fingerprint,
            model=fixture.model, create=lambda *a, **kw: (calls.append(a), fixture.response())[1])
        with tempfile.TemporaryDirectory() as directory:
            settings = SimpleNamespace(data_dir=Path(directory))
            result = execute_quick_screen(settings, task, provider, ops)
            self.assertEqual(result["state"], "completed", result)
            self.assertEqual(len(calls), 1)
            parent["cancel_requested"] = True
            revoked = execute_quick_screen(settings, task, provider, ops)
            self.assertEqual(revoked["state"], "quick_unknown")
            parent["cancel_requested"] = False
            plan["ranking"] = {"decisions": []}
            changed = execute_quick_screen(settings, task, provider, ops)
            self.assertEqual(changed["state"], "quick_unknown")
            self.assertEqual(len(calls), 1)

    def test_modified_evidence_after_consent_never_reaches_provider(self):
        from src.workbench.progressive_triage.quick_screen_operation import execute_quick_screen
        from types import SimpleNamespace

        fixture, task = self._task()
        task["spec"]["evidence"] = [{**task["spec"]["evidence"][0], "text": "changed source"}]

        class Provider:
            configured = True
            fingerprint = fixture.provider_fingerprint
            model = fixture.model
            calls = 0

            def create(self, *args, **kwargs):
                self.calls += 1
                raise AssertionError("modified consent payload must not be sent")

        provider = Provider()
        with tempfile.TemporaryDirectory() as directory:
            result = execute_quick_screen(SimpleNamespace(data_dir=Path(directory)), task, provider)
        self.assertEqual(result["state"], "quick_unknown")
        self.assertEqual(provider.calls, 0)


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

    def test_cumulative_token_call_and_time_values_are_advisory_only(self):
        with tempfile.TemporaryDirectory() as directory:
            limits = {
                **build_policy()["limits"],
                "quick_screen_groups_per_audit": 130,
                "deep_groups_per_audit": 0,
                "max_model_calls_per_audit": 120,
                "max_input_tokens_per_audit": 1_024,
                "max_output_tokens_per_audit": 256,
                "max_ai_wall_seconds": 60,
                "max_model_concurrency": 1,
            }
            policy = build_policy("custom", limits, True)
            ledger, policy, sha = self.create(directory, policy)
            ledger.create_audit("audit-no-cumulative-cap", policy, sha)
            db = ledger._connect()
            try:
                db.execute("UPDATE audit_budget SET created_at=0 WHERE audit_id=?",
                           ("audit-no-cumulative-cap",))
            finally:
                db.close()

            for index in range(130):
                group_id = f"group-{index}"
                endpoint_id = f"endpoint-{index}"
                ledger.dispatch_group("audit-no-cumulative-cap", group_id, endpoint_id,
                                      "quick_screen", evidence_gate="ranked_and_selected")
                reservation = ledger.reserve(
                    "audit-no-cumulative-cap", f"request-{index}", endpoint_id, group_id,
                    "quick_screen", max_input_tokens=1_000, max_output_tokens=512,
                )
                settled = ledger.settle(
                    reservation["reservation_id"], outcome="completed",
                    input_tokens=1_500, output_tokens=700,
                    quick_assessment="investigate",
                )
                self.assertEqual(settled["status"], "completed")

            snapshot = ledger.get("audit-no-cumulative-cap")
            self.assertEqual(snapshot["status"], "active")
            self.assertIsNone(snapshot["stop_reason"])
            self.assertEqual(snapshot["usage"]["model_calls_allocated"], 130)
            self.assertEqual(snapshot["usage"]["input_tokens_allocated"], 195_000)
            self.assertEqual(snapshot["usage"]["output_tokens_allocated"], 91_000)
            self.assertFalse(snapshot["usage"]["cumulative_usage_limits_enforced"])
            self.assertIsNone(snapshot["usage"]["max_model_calls"])
            self.assertIsNone(snapshot["usage"]["max_input_tokens"])
            self.assertIsNone(snapshot["usage"]["max_output_tokens"])
            self.assertIsNone(snapshot["usage"]["wall_seconds_remaining"])

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

    def test_budgeted_agent_client_settles_usage_and_never_replays_unknown_calls(self):
        from src.workbench.progressive_triage.deep_agent_operation import BudgetedAgentClient
        from src.workbench.progressive_triage.ledger import BudgetError

        class FakeClient:
            timeout = 10
            def __init__(self, response=None, error=None):
                self.response, self.error, self.calls = response, error, 0
            def create_with_timeout(self, payload, timeout, max_retries=None):
                self.calls += 1
                if self.error:
                    raise self.error
                return self.response

        with tempfile.TemporaryDirectory() as directory:
            ledger, policy, sha = self.create(directory)
            ledger.create_audit("audit-client", policy, sha)
            ledger.dispatch_group("audit-client", "group-client", "endpoint-client",
                                  "quick_screen", evidence_gate="ranked_and_selected")
            quick = ledger.reserve("audit-client", "quick-client", "endpoint-client", "group-client",
                                   "quick_screen", max_input_tokens=1000, max_output_tokens=512)
            ledger.settle(quick["reservation_id"], outcome="completed", input_tokens=20,
                          output_tokens=10, quick_assessment="investigate")
            ledger.dispatch_group("audit-client", "group-client", "endpoint-client",
                                  "deep_agent", evidence_gate="quick_screen_investigate")
            client = FakeClient({"usage": {"input_tokens": 80, "output_tokens": 40}})
            wrapped = BudgetedAgentClient(client, ledger, audit_id="audit-client", operation_id="op-client",
                                          endpoint_id="endpoint-client", group_id="group-client")
            wrapped.set_budget_phase("skeptic_review")
            wrapped.create_with_timeout({"max_output_tokens": 128}, 10)
            self.assertEqual(client.calls, 1)
            usage = ledger.get("audit-client")["usage"]
            self.assertEqual(usage["model_calls_allocated"], 2)
            self.assertEqual(usage["input_tokens_allocated"], 100)
            self.assertEqual(usage["output_tokens_allocated"], 50)
            self.assertEqual(usage["by_phase"]["skeptic"]["model_calls_completed"], 1)

        with tempfile.TemporaryDirectory() as directory:
            ledger, policy, sha = self.create(directory)
            ledger.create_audit("audit-unknown", policy, sha)
            ledger.dispatch_group("audit-unknown", "group-unknown", "endpoint-unknown",
                                  "quick_screen", evidence_gate="ranked_and_selected")
            quick = ledger.reserve("audit-unknown", "quick-unknown", "endpoint-unknown", "group-unknown",
                                   "quick_screen", max_input_tokens=1000, max_output_tokens=512)
            ledger.settle(quick["reservation_id"], outcome="completed", input_tokens=20,
                          output_tokens=10, quick_assessment="investigate")
            ledger.dispatch_group("audit-unknown", "group-unknown", "endpoint-unknown",
                                  "deep_agent", evidence_gate="quick_screen_investigate")
            client = FakeClient(error=TimeoutError("ambiguous Provider timeout"))
            wrapped = BudgetedAgentClient(client, ledger, audit_id="audit-unknown", operation_id="op-unknown",
                                          endpoint_id="endpoint-unknown", group_id="group-unknown")
            with self.assertRaises(TimeoutError):
                wrapped.create_with_timeout({"max_output_tokens": 128}, 10)
            with self.assertRaises(BudgetError):
                wrapped.create_with_timeout({"max_output_tokens": 128}, 10)
            self.assertEqual(client.calls, 1)
            usage = ledger.get("audit-unknown")["usage"]
            self.assertEqual(usage["model_calls_allocated"], 2)
            self.assertEqual(usage["model_calls_in_flight"], 0)
            self.assertEqual(usage["by_phase"]["deep_agent"]["model_calls_unknown"], 1)

    def test_deep_dispatch_stays_open_across_all_agent_model_phases(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger, policy, sha = self.create(directory)
            ledger.create_audit("audit-phases", policy, sha)
            ledger.dispatch_group("audit-phases", "group-1", "endpoint-1",
                                  "quick_screen", evidence_gate="ranked_and_selected")
            quick = ledger.reserve("audit-phases", "quick", "endpoint-1", "group-1",
                                   "quick_screen", max_input_tokens=100, max_output_tokens=50)
            ledger.settle(quick["reservation_id"], outcome="completed", input_tokens=20,
                          output_tokens=10, quick_assessment="investigate")
            ledger.dispatch_group("audit-phases", "group-1", "endpoint-1",
                                  "deep_agent", evidence_gate="quick_screen_investigate")
            ledger.claim_deep_operation("audit-phases", "group-1", "endpoint-1", "deep-operation")
            for index, phase in enumerate(("deep_agent", "structured_repair", "skeptic", "report")):
                reservation = ledger.reserve(
                    "audit-phases", "deep-" + str(index), "endpoint-1", "group-1",
                    "deep_agent", phase=phase, max_input_tokens=100, max_output_tokens=50,
                )
                ledger.settle(reservation["reservation_id"], outcome="completed",
                              input_tokens=20, output_tokens=10)
                dispatch = ledger._connect()
                try:
                    state = dispatch.execute(
                        "SELECT status FROM triage_dispatch WHERE audit_id=? AND group_id=? AND stage='deep_agent'",
                        ("audit-phases", "group-1"),
                    ).fetchone()[0]
                finally:
                    dispatch.close()
                self.assertEqual(state, "running")

            ledger.finish_deep_group("audit-phases", "group-1", "endpoint-1",
                                     "deep-operation", success=True)
            usage = ledger.get("audit-phases")["usage"]
            self.assertEqual(usage["model_calls_allocated"], 5)
            self.assertEqual(set(usage["by_phase"]), {"quick_screen", "deep_agent", "structured_repair", "skeptic", "report"})
            self.assertEqual(usage["by_phase"]["report"]["model_calls_completed"], 1)

    def test_existing_budget_ledger_migrates_phase_labels_and_preserves_quick_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger, policy, sha = self.create(directory)
            ledger.create_audit("audit-legacy-phase", policy, sha)
            ledger.dispatch_group("audit-legacy-phase", "group-1", "endpoint-1",
                                  "quick_screen", evidence_gate="ranked_and_selected")
            reservation = ledger.reserve("audit-legacy-phase", "quick", "endpoint-1", "group-1",
                                         "quick_screen", max_input_tokens=100, max_output_tokens=50)
            ledger.settle(reservation["reservation_id"], outcome="completed",
                          input_tokens=20, output_tokens=10, quick_assessment="investigate")
            db = ledger._connect()
            try:
                db.execute("ALTER TABLE budget_reservation DROP COLUMN phase")
            finally:
                db.close()

            migrated = self.BudgetLedger(Path(directory) / "triage-budget.sqlite")
            db = migrated._connect()
            try:
                columns = {row[1] for row in db.execute("PRAGMA table_info(budget_reservation)")}
                saved_phase = db.execute(
                    "SELECT phase FROM budget_reservation WHERE audit_id=?", ("audit-legacy-phase",),
                ).fetchone()[0]
            finally:
                db.close()
            self.assertIn("phase", columns)
            self.assertEqual(saved_phase, "quick_screen")
            self.assertEqual(migrated.get("audit-legacy-phase")["usage"]["by_phase"]["quick_screen"]["model_calls_completed"], 1)

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


class ProgressiveDeepApiIntegrationTests(unittest.TestCase):
    def test_deep_preview_and_start_bind_uncapped_agent_and_l2_result(self):
        import os
        from unittest.mock import patch
        from src.workbench.operations_store import Operations
        from src.workbench.progressive_triage.policy import policy_envelope
        quick_id = "a" * 32
        policy = build_policy()
        frozen = {"revision": 0, **policy_envelope(policy)}
        quick = {"id": quick_id, "kind": "progressive_quick_screen", "status": "completed",
                 "result_sha256": "d" * 64,
                 "spec": {"job_id": "job-1", "candidate_id": "candidate-1",
                          "audit_operation_id": "job-1", "progressive_policy": frozen,
                          "group": {"group_id": "group-1"},
                          "authorization": {"report_sha256": "b" * 64}}}
        quick_result = {"quick_screen": {"state": "completed", "quick_assessment": "investigate"},
                        "source_binding": {"report_sha256": "b" * 64, "commit": "c" * 40}}
        original_get = Operations.get
        def get(ops, key):
            return quick if key == quick_id else original_get(ops, key)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = create_app(Settings(root / "data", (root / "targets",)))
            repo = app.state.store.add_repository("openharmony/sample", str(root))
            job = {"id": "job-1", "repository_id": repo["id"], "status": "completed",
                   "report_sha256": "b" * 64}
            report = {"repository": "openharmony/sample", "commit": "c" * 40}
            candidate = {"id": "candidate-1", "file": "src/sample.cpp", "line": 1,
                         "source_sha256": "a" * 64, "evidence": {"obligations": [{
                             "kind": "callee_and_policy", "description": "review source binding", "status": "unknown"}]}}
            source = {"sha256": "a" * 64, "blob": "f" * 40, "text": "int check() {}"}
            with TestClient(app) as client, patch.dict(os.environ, {
                    "OHSCANNER_LLM_MODEL": "review-model", "OHSCANNER_LLM_API_KEY": "test-secret"}), \
                    patch.object(app.state.store, "job", return_value=job), \
                    patch("src.workbench.operations_api.service.read_report", return_value=report), \
                    patch("src.workbench.operations_api.service.finding", return_value=candidate), \
                    patch("src.workbench.operations_api.service.source", return_value=source), \
                    patch.object(Operations, "get", get), \
                    patch.object(Operations, "result", return_value=quick_result):
                headers = {"x-ohscanner-client": "workbench-v1"}
                body = {"job_id": "job-1", "candidate_id": "candidate-1", "mode": "tool_agent",
                        "progressive_quick_screen_operation_id": quick_id}
                endpoint = "/api/v1/operations/progressive-deep-investigations"
                response = client.post(endpoint + "/preview", headers=headers, json=body)
                self.assertEqual(response.status_code, 200, response.text)
                preview = response.json()
                self.assertEqual(preview["budgets"]["local_cumulative_token_budget"], "none")
                self.assertEqual(preview["budgets"]["local_total_model_call_budget"], "none")
                self.assertEqual(preview["budgets"]["local_total_wall_time_budget"], "until_terminal_condition")
                self.assertFalse(preview["budgets"]["cumulative_usage_limits_enforced"])
                self.assertEqual(preview["progressive_binding"]["quick_screen_result_sha256"], quick["result_sha256"])
                approved = {**body, "source_submission_approved": True,
                            "consent_nonce": preview["consent_nonce"], "consent_sha256": preview["consent_sha256"]}
                started = client.post(endpoint, headers=headers, json=approved)
                self.assertEqual(started.status_code, 201, started.text)
                spec = started.json()["spec"]
                self.assertTrue(spec["no_cumulative_token_ceiling"])
                self.assertTrue(spec["continuous_investigation"])
                self.assertEqual(spec["max_provider_retries"], 0)
                replay = client.post(endpoint, headers=headers, json=approved)
                self.assertEqual(replay.json()["id"], started.json()["id"])
                quick_result["quick_screen"]["quick_assessment"] = "insufficient_context"
                rejected = client.post(endpoint + "/preview", headers=headers, json=body)
                self.assertEqual(rejected.status_code, 409)

    def test_deep_preview_accepts_one_investigate_member_from_l2_batch(self):
        import os
        from unittest.mock import patch
        from src.workbench.operations_store import Operations
        from src.workbench.progressive_triage.policy import policy_envelope

        batch_id = "a" * 32
        group_id = "group-1"
        policy = build_policy()
        frozen = {"revision": 0, **policy_envelope(policy)}
        child_spec = {"job_id": "job-1", "candidate_id": "candidate-1",
                      "audit_operation_id": "job-1", "progressive_policy": frozen,
                      "group": {"group_id": group_id},
                      "authorization": {"report_sha256": "b" * 64}}
        batch = {"id": batch_id, "kind": "progressive_quick_screen_batch",
                 "status": "completed", "result_sha256": "d" * 64,
                 "spec": {"audit_operation_id": "job-1", "items": [
                     {"group_id": group_id, "spec": child_spec}]}}
        quick_result = {"quick_screen": {"state": "completed", "quick_assessment": "investigate"},
                        "source_binding": {"report_sha256": "b" * 64, "commit": "c" * 40}}
        batch_result = {"groups": [{"group_id": group_id, "candidate_id": "candidate-1",
                                    "state": "completed", "result": quick_result}]}
        original_get = Operations.get
        original_result = Operations.result

        def get(ops, key):
            return batch if key == batch_id else original_get(ops, key)

        def result(ops, key):
            return batch_result if key == batch_id else original_result(ops, key)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            app = create_app(Settings(root / "data", (root / "targets",)))
            repo = app.state.store.add_repository("openharmony/sample", str(root))
            job = {"id": "job-1", "repository_id": repo["id"], "status": "completed",
                   "report_sha256": "b" * 64}
            report = {"repository": "openharmony/sample", "commit": "c" * 40}
            candidate = {"id": "candidate-1", "file": "src/sample.cpp", "line": 1,
                         "source_sha256": "a" * 64, "evidence": {"obligations": [{
                             "kind": "callee_and_policy", "description": "review source binding", "status": "unknown"}]}}
            source = {"sha256": "a" * 64, "blob": "f" * 40, "text": "int check() {}"}
            with TestClient(app) as client, patch.dict(os.environ, {
                    "OHSCANNER_LLM_MODEL": "review-model", "OHSCANNER_LLM_API_KEY": "test-secret"}), \
                    patch.object(app.state.store, "job", return_value=job), \
                    patch("src.workbench.operations_api.service.read_report", return_value=report), \
                    patch("src.workbench.operations_api.service.finding", return_value=candidate), \
                    patch("src.workbench.operations_api.service.source", return_value=source), \
                    patch.object(Operations, "get", get), patch.object(Operations, "result", result):
                headers = {"x-ohscanner-client": "workbench-v1"}
                body = {"job_id": "job-1", "candidate_id": "candidate-1", "mode": "tool_agent",
                        "progressive_quick_screen_operation_id": batch_id,
                        "progressive_group_id": group_id}
                endpoint = "/api/v1/operations/progressive-deep-investigations"
                response = client.post(endpoint + "/preview", headers=headers, json=body)
                self.assertEqual(response.status_code, 200, response.text)
                preview = response.json()
                self.assertEqual(preview["progressive_binding"]["quick_screen_operation_id"], batch_id)
                self.assertEqual(preview["progressive_binding"]["quick_screen_batch_group_id"], group_id)
                approved = {**body, "source_submission_approved": True,
                            "consent_nonce": preview["consent_nonce"], "consent_sha256": preview["consent_sha256"]}
                started = client.post(endpoint, headers=headers, json=approved)
                self.assertEqual(started.status_code, 201, started.text)
                self.assertEqual(started.json()["spec"]["progressive_quick_screen_batch_group_id"], group_id)


class QuickScreenFailureDiagnosticsTests(unittest.TestCase):
    def test_safe_http_diagnostics_preserve_status_and_do_not_echo_body(self):
        from src.workbench.progressive_triage.quick_screen import _quick_screen_failure
        for status in (400, 401, 403, 404, 429, 500):
            with self.subTest(status=status):
                result = _quick_screen_failure(ValueError(f"LLM provider returned HTTP {status}"))
                self.assertEqual(result["reason_code"], f"provider_http_{status}")
                self.assertEqual(result["failure"]["http_status"], status)
                self.assertTrue(result["failure"]["suggestion"])
        result = _quick_screen_failure(RuntimeError("Bearer private-key; source: secret source"))
        self.assertNotIn("private-key", str(result))
        self.assertNotIn("secret source", str(result))
        self.assertEqual(result["failure"]["error_type"], "RuntimeError")

    def test_schema_json_and_local_client_errors_are_distinguished(self):
        import json
        from src.workbench.progressive_triage.quick_screen import _quick_screen_failure
        from src.workbench.agent import ProviderConfig
        try:
            ProviderConfig("https://api.example.invalid/v1", "test", "private-test-key").create({})
        except AttributeError as error:
            wiring_error = error
        cases = [
            (wiring_error, "provider_client_error", "client_setup"),
            (ValueError("quick_screen_citation_invalid"), "quick_screen_citation_invalid", "response_validation"),
            (json.JSONDecodeError("private source", "private source", 0), "provider_invalid_json", "response_validation"),
        ]
        for error, code, stage in cases:
            with self.subTest(code=code):
                result = _quick_screen_failure(error)
                self.assertEqual(result["reason_code"], code)
                self.assertEqual(result["failure"]["stage"], stage)
                self.assertNotIn("private", str(result))


class QuickScreenRetrySingleFlightTests(unittest.TestCase):
    def test_fresh_consent_cannot_start_while_another_call_is_in_flight(self):
        from src.workbench.progressive_triage.ledger import BudgetLedger, BudgetError
        with tempfile.TemporaryDirectory() as directory:
            ledger = BudgetLedger(Path(directory) / "ledger.sqlite3")
            policy = build_policy()
            ledger.create_audit("audit-1", policy, content_sha256(policy))
            ledger.dispatch_group("audit-1", "group-1", "endpoint-1", "quick_screen", evidence_gate="ranked_and_selected")
            first = ledger.reserve("audit-1", "consent-1", "endpoint-1", "group-1", "quick_screen",
                                   max_input_tokens=1000, max_output_tokens=512, reauthorized_quick_screen=True)
            with self.assertRaisesRegex(BudgetError, "in-flight"):
                ledger.reserve("audit-1", "consent-2", "endpoint-1", "group-1", "quick_screen",
                               max_input_tokens=1000, max_output_tokens=512, reauthorized_quick_screen=True)
            ledger.settle(first["reservation_id"], outcome="unknown_outcome")
            second = ledger.reserve("audit-1", "consent-2", "endpoint-1", "group-1", "quick_screen",
                                    max_input_tokens=1000, max_output_tokens=512, reauthorized_quick_screen=True)
            self.assertFalse(second["idempotent_replay"])
            self.assertNotEqual(first["reservation_id"], second["reservation_id"])


class QuickScreenLateFailureTests(unittest.TestCase):
    def test_unproven_transport_attribute_error_must_not_release_charged_reservation(self):
        from src.workbench.progressive_triage.quick_screen import _quick_screen_failure
        error = AttributeError("private provider state", name="response_headers", obj=object())
        result = _quick_screen_failure(error)
        self.assertEqual(result["failure"]["request_outcome"], "unknown")
        self.assertNotIn("private provider state", str(result))

    def test_non_object_provider_response_is_a_response_shape_failure(self):
        from types import SimpleNamespace
        fixture = QuickScreenTests()
        fixture.setUp()
        result = fixture.run(SimpleNamespace(create=lambda *_args, **_kwargs: []),
            fixture.group, fixture.evidence, fixture.authorization,
            provider_fingerprint=fixture.provider_fingerprint, model=fixture.model)
        self.assertEqual(result["reason_code"], "provider_response_shape_invalid")
        self.assertEqual(result["failure"]["request_outcome"], "response_received")
