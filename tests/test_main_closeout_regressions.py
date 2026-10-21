"""Regression for the audited mainline Agent and triage integration gates."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from src.workbench.operation_worker import _hard_deadline_seconds
from src.workbench.progressive_triage.deep_agent_operation import BudgetedAgentClient
from src.workbench.progressive_triage.ledger import BudgetConflict, BudgetError, BudgetLedger
from src.workbench.progressive_triage.policy import build_policy, policy_envelope


class WorkerDeadlineContractTests(unittest.TestCase):
    def test_uncapped_ordinary_agent_has_no_legacy_parent_deadline(self):
        spec = {"no_cumulative_token_ceiling": True, "timeout_seconds": 120}
        self.assertIsNone(_hard_deadline_seconds({"kind": "agent_investigation", "spec": spec}))
        self.assertEqual(_hard_deadline_seconds({"kind": "progressive_quick_screen", "spec": spec}), 100)

    def test_bounded_progressive_agent_keeps_its_parent_deadline(self):
        spec = {"no_cumulative_token_ceiling": False, "timeout_seconds": 120,
                "progressive_quick_screen_operation_id": "a" * 32}
        self.assertEqual(_hard_deadline_seconds({"kind": "agent_investigation", "spec": spec}), 130)
        spec["no_cumulative_token_ceiling"] = True
        self.assertEqual(_hard_deadline_seconds({"kind": "agent_investigation", "spec": spec}), 130)


class MultiRequestDeepGroupTests(unittest.TestCase):
    def prepared(self, root):
        policy = build_policy()
        ledger = BudgetLedger(Path(root) / "budget.sqlite3")
        ledger.create_audit("audit", policy, policy_envelope(policy)["policy_sha256"])
        ledger.dispatch_group("audit", "group", "scan", "quick_screen",
                              evidence_gate="ranked_and_selected")
        quick = ledger.reserve("audit", "quick", "scan", "group", "quick_screen",
                               max_input_tokens=1000, max_output_tokens=512)
        ledger.settle(quick["reservation_id"], outcome="completed", input_tokens=100,
                      output_tokens=20, quick_assessment="investigate")
        ledger.dispatch_group("audit", "group", "scan", "deep_agent",
                              evidence_gate="quick_screen_investigate")
        return ledger

    @staticmethod
    def status(ledger):
        with sqlite3.connect(ledger.path) as db:
            return db.execute("SELECT status FROM triage_dispatch WHERE audit_id='audit' AND group_id='group' AND stage='deep_agent'").fetchone()[0]

    def test_second_model_request_succeeds_before_group_completion(self):
        class Client:
            timeout = 10
            def __init__(self):
                self.calls = 0
            def create_with_timeout(self, payload, timeout, max_retries=None):
                self.calls += 1
                self_test.assertEqual(max_retries, 0)
                return {"usage": {"input_tokens": 100, "output_tokens": 40}}

        self_test = self
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.prepared(directory)
            ledger.claim_deep_operation("audit", "group", "scan", "operation")
            provider = Client()
            wrapped = BudgetedAgentClient(provider, ledger, audit_id="audit",
                operation_id="operation", endpoint_id="scan", group_id="group")
            wrapped.create_with_timeout({"max_output_tokens": 128}, 10)
            self.assertEqual(self.status(ledger), "running")
            wrapped.create_with_timeout({"max_output_tokens": 128}, 10)
            self.assertEqual(provider.calls, 2)
            self.assertEqual(self.status(ledger), "running")
            ledger.finish_deep_group("audit", "group", "scan", "operation", success=True)
            self.assertEqual(self.status(ledger), "completed")
            self.assertEqual(ledger.get("audit")["usage"]["model_calls_allocated"], 3)
            with self.assertRaises(BudgetError):
                wrapped.create_with_timeout({"max_output_tokens": 128}, 10)
            self.assertEqual(provider.calls, 2)

    def test_other_operation_cannot_double_run_one_group(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.prepared(directory)
            ledger.claim_deep_operation("audit", "group", "scan", "operation-1")
            ledger.claim_deep_operation("audit", "group", "scan", "operation-1")
            with self.assertRaises(BudgetConflict):
                ledger.claim_deep_operation("audit", "group", "scan", "operation-2")
            ledger.finish_deep_group("audit", "group", "scan", "operation-1", success=False)
            self.assertEqual(self.status(ledger), "partial")
            with self.assertRaises(BudgetError):
                ledger.claim_deep_operation("audit", "group", "scan", "operation-1")

    def test_unknown_second_response_fails_closed(self):
        class Client:
            timeout = 10
            def __init__(self):
                self.calls = 0
            def create_with_timeout(self, payload, timeout, max_retries=None):
                self.calls += 1
                if self.calls == 2:
                    raise TimeoutError("response unknown")
                return {"usage": {"input_tokens": 100, "output_tokens": 40}}

        with tempfile.TemporaryDirectory() as directory:
            ledger = self.prepared(directory)
            ledger.claim_deep_operation("audit", "group", "scan", "operation")
            provider = Client()
            wrapped = BudgetedAgentClient(provider, ledger, audit_id="audit",
                operation_id="operation", endpoint_id="scan", group_id="group")
            wrapped.create_with_timeout({"max_output_tokens": 128}, 10)
            with self.assertRaises(TimeoutError):
                wrapped.create_with_timeout({"max_output_tokens": 128}, 10)
            self.assertEqual(self.status(ledger), "partial")
            with self.assertRaises(BudgetError):
                wrapped.create_with_timeout({"max_output_tokens": 128}, 10)
            self.assertEqual(provider.calls, 2)
            with self.assertRaises(BudgetError):
                ledger.finish_deep_group("audit", "group", "scan", "operation", success=True)

    @unittest.skipIf(sqlite3.sqlite_version_info < (3, 35, 0), "SQLite DROP COLUMN unavailable")
    def test_existing_sqlite_ledger_is_migrated(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "budget.sqlite3"
            BudgetLedger(path)
            with sqlite3.connect(path) as db:
                db.execute("ALTER TABLE triage_dispatch DROP COLUMN deep_operation_id")
                db.commit()
            BudgetLedger(path)
            with sqlite3.connect(path) as db:
                fields = {row[1] for row in db.execute("PRAGMA table_info(triage_dispatch)")}
            self.assertIn("deep_operation_id", fields)

    def test_complete_agent_workflow_finishes_only_after_two_requests(self):
        from types import SimpleNamespace
        from unittest.mock import patch
        from src.workbench.progressive_triage.deep_agent_operation import execute_progressive_deep_agent
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.prepared(directory)
            spec = {"progressive_audit_operation_id": "audit", "progressive_group_id": "group",
                    "job_id": "scan", "progressive_quick_screen_operation_id": "quick",
                    "provider_fingerprint": "provider"}
            task = {"id": "operation", "spec": spec}
            calls = []
            provider = SimpleNamespace(configured=True, fingerprint="provider")
            client = SimpleNamespace(timeout=10, create_with_timeout=lambda *a, **kw:
                                     (calls.append(kw), {"usage": {"input_tokens": 100, "output_tokens": 40}})[1])
            def agent(*a, client):
                for _ in range(2):
                    client.create_with_timeout({"max_output_tokens": 128}, 10)
                    self.assertEqual(self.status(ledger), "running")
                return {"status": "completed"}
            with patch("src.workbench.progressive_triage.deep_agent_operation.progressive_gate", return_value=(spec, ledger)), \
                 patch("src.workbench.agent.ProviderConfig.from_env", return_value=provider), \
                 patch("src.workbench.agent.ResponsesClient", return_value=client), \
                 patch("src.workbench.agent.execute_agent", side_effect=agent):
                result = execute_progressive_deep_agent(SimpleNamespace(data_dir=Path(directory)), None,
                    SimpleNamespace(get=lambda _: {"status": "running", "cancel_requested": False}), task)
            self.assertEqual(self.status(ledger), "completed")
            self.assertEqual(len(calls), 2)
            self.assertEqual(result["progressive_triage"]["budget"]["usage"]["model_calls_allocated"], 3)

    def test_cancelled_dispatch_never_sends_or_spends_reserved_call(self):
        class Client:
            timeout = 10
            def create_with_timeout(self, *a, **kw):
                raise AssertionError("cancelled request must not leave the process")
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.prepared(directory)
            checks = []
            def cancel_after_reservation():
                checks.append(True)
                if len(checks) == 2:
                    raise InterruptedError("parent cancelled during reservation")
            wrapped = BudgetedAgentClient(Client(), ledger, audit_id="audit", operation_id="op",
                endpoint_id="scan", group_id="group", before_request=cancel_after_reservation)
            with self.assertRaises(InterruptedError):
                wrapped.create_with_timeout({"max_output_tokens": 128}, 10)
            self.assertEqual(ledger.get("audit")["usage"]["model_calls_allocated"], 1)
            self.assertEqual(self.status(ledger), "partial")

    def test_request_timeout_is_clamped_to_shared_remaining_time(self):
        from unittest.mock import patch
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.prepared(directory)
            snapshot = ledger.get("audit")
            snapshot["usage"]["wall_seconds_remaining"] = 6
            calls = []
            client = SimpleNamespace(create_with_timeout=lambda *a, **kw:
                (calls.append((a, kw)), {"usage": {"input_tokens": 10, "output_tokens": 5}})[1])
            wrapped = BudgetedAgentClient(client, ledger, audit_id="audit", operation_id="op",
                                          endpoint_id="scan", group_id="group")
            with patch.object(ledger, "get", return_value=snapshot):
                wrapped.create_with_timeout({"max_output_tokens": 128}, 45)
            self.assertEqual(calls[0][0][1], 5)
            self.assertEqual(calls[0][1]["max_retries"], 0)

    def test_group_claim_is_atomic_between_operations(self):
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.prepared(directory)
            def claim(operation):
                try:
                    ledger.claim_deep_operation("audit", "group", "scan", operation)
                    return "claimed"
                except BudgetConflict:
                    return "conflict"
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(pool.map(claim, ["op-a", "op-b"]))
            self.assertCountEqual(results, ["claimed", "conflict"])

    @unittest.skipIf(sqlite3.sqlite_version_info < (3, 35, 0), "SQLite DROP COLUMN unavailable")
    def test_legacy_schema_migration_is_serialized(self):
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory() as directory:
            ledger = self.prepared(directory)
            with sqlite3.connect(ledger.path) as db:
                db.execute("ALTER TABLE triage_dispatch DROP COLUMN deep_operation_id")
            with ThreadPoolExecutor(max_workers=4) as pool:
                list(pool.map(lambda _: BudgetLedger(ledger.path), range(4)))
            ledger.claim_deep_operation("audit", "group", "scan", "migrated-op")

    def test_concurrent_workers_can_create_one_new_ledger(self):
        from concurrent.futures import ThreadPoolExecutor
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "new.sqlite3"
            with ThreadPoolExecutor(max_workers=4) as pool:
                ledgers = list(pool.map(lambda _: BudgetLedger(path), range(4)))
            self.assertEqual(len(ledgers), 4)
            with sqlite3.connect(path) as db:
                columns = {row[1] for row in db.execute("PRAGMA table_info(triage_dispatch)")}
            self.assertIn("deep_operation_id", columns)


if __name__ == "__main__":
    unittest.main()
