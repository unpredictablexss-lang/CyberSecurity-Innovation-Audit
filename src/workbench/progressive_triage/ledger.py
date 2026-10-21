"""Transactional usage accounting and scheduling for progressive AI triage.

The ledger records usage and enforces concurrency. It does not cap cumulative
tokens, model calls, or investigation duration; Provider availability and
per-request service limits still apply. USD remains advisory.
"""
from __future__ import annotations

from contextlib import closing
from decimal import Decimal, InvalidOperation
import json
import os
from pathlib import Path
import stat
import sqlite3
import time
import uuid
from typing import Any

from .policy import policy_envelope, validate_policy


class BudgetError(ValueError):
    pass


class BudgetConflict(BudgetError):
    pass


class BudgetLedger:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        parent_stat = os.stat(self.path.parent, follow_symlinks=False)
        if not stat.S_ISDIR(parent_stat.st_mode) or parent_stat.st_mode & 0o077:
            raise BudgetError("budget ledger directory must be private and non-symlinked")
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(self.path, os.O_RDWR | nofollow)
        except FileNotFoundError:
            try:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_RDWR | nofollow, 0o600)
            except FileExistsError:
                # Another Worker created the ledger after our first open.
                fd = os.open(self.path, os.O_RDWR | nofollow)
        try:
            metadata = os.fstat(fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o077:
                raise BudgetError("budget ledger must be a private regular file")
        finally:
            os.close(fd)
        with closing(self._connect()) as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS audit_budget (
                    audit_id TEXT PRIMARY KEY, policy_json TEXT NOT NULL,
                    policy_sha256 TEXT NOT NULL, created_at REAL NOT NULL,
                    status TEXT NOT NULL, stop_reason TEXT,
                    cost_enforcement TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS triage_dispatch (
                    audit_id TEXT NOT NULL REFERENCES audit_budget(audit_id),
                    group_id TEXT NOT NULL, endpoint_id TEXT NOT NULL,
                    stage TEXT NOT NULL CHECK(stage IN ('quick_screen','deep_agent')),
                    evidence_gate TEXT NOT NULL, quick_assessment TEXT,
                    status TEXT NOT NULL, created_at REAL NOT NULL,
                    PRIMARY KEY(audit_id, group_id, stage)
                );
                CREATE TABLE IF NOT EXISTS budget_reservation (
                    reservation_id TEXT PRIMARY KEY,
                    audit_id TEXT NOT NULL REFERENCES audit_budget(audit_id),
                    idempotency_key TEXT NOT NULL, endpoint_id TEXT NOT NULL,
                    group_id TEXT NOT NULL,
                    stage TEXT NOT NULL CHECK(stage IN ('quick_screen','deep_agent')),
                    phase TEXT NOT NULL DEFAULT 'deep_agent' CHECK(phase IN ('quick_screen','deep_agent','structured_repair','skeptic','report')),
                    max_input_tokens INTEGER NOT NULL, max_output_tokens INTEGER NOT NULL,
                    status TEXT NOT NULL, actual_input_tokens INTEGER,
                    actual_output_tokens INTEGER, estimated_cost_usd TEXT,
                    created_at REAL NOT NULL, finished_at REAL,
                    UNIQUE(audit_id, idempotency_key)
                );
                CREATE INDEX IF NOT EXISTS idx_budget_reservation_audit_status
                    ON budget_reservation(audit_id, status);
            """)
            # Serialise schema migration across concurrent Worker processes;
            # the old SQLite ledger can be opened safely by the new release.
            db.execute("BEGIN IMMEDIATE")
            columns = {row[1] for row in db.execute("PRAGMA table_info(triage_dispatch)")}
            if "quick_assessment" not in columns:
                db.execute("ALTER TABLE triage_dispatch ADD COLUMN quick_assessment TEXT")
            if "deep_operation_id" not in columns:
                db.execute("ALTER TABLE triage_dispatch ADD COLUMN deep_operation_id TEXT")
            reservation_columns = {row[1] for row in db.execute("PRAGMA table_info(budget_reservation)")}
            if "phase" not in reservation_columns:
                db.execute("ALTER TABLE budget_reservation ADD COLUMN phase TEXT NOT NULL DEFAULT 'deep_agent' CHECK(phase IN ('quick_screen','deep_agent','structured_repair','skeptic','report'))")
                db.execute("UPDATE budget_reservation SET phase='quick_screen' WHERE stage='quick_screen'")
            db.commit()

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA busy_timeout=15000")
        db.execute("PRAGMA foreign_keys=ON")
        return db

    @staticmethod
    def _id(value: Any, label: str, max_length: int = 200) -> str:
        if not isinstance(value, str) or not value.strip() or len(value) > max_length:
            raise BudgetError(f"invalid {label}")
        return value

    @staticmethod
    def _now() -> float:
        return time.time()

    def create_audit(self, audit_id: str, policy: dict[str, Any],
                     policy_sha256: str, *, strict_cost: bool = False) -> dict[str, Any]:
        audit_id = self._id(audit_id, "audit ID")
        policy = validate_policy(policy)
        expected = policy_envelope(policy)["policy_sha256"]
        if policy_sha256 != expected:
            raise BudgetError("policy SHA does not match the frozen policy")
        if not isinstance(strict_cost, bool):
            raise BudgetError("strict_cost must be boolean")
        if strict_cost:
            raise BudgetError("strict USD budget is unavailable without a verified Provider-side cap")
        cost_mode = "advisory_only"
        policy_json = json.dumps(policy, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT * FROM audit_budget WHERE audit_id=?", (audit_id,)).fetchone()
            if prior:
                if prior["policy_sha256"] != policy_sha256 or prior["policy_json"] != policy_json:
                    db.rollback()
                    raise BudgetConflict("audit already has a different frozen policy")
                db.commit()
                return self.get(audit_id)
            db.execute(
                "INSERT INTO audit_budget VALUES(?,?,?,?,?,?,?)",
                (audit_id, policy_json, policy_sha256, self._now(), "active", None, cost_mode),
            )
            db.commit()
        return self.get(audit_id)

    def dispatch_group(self, audit_id: str, group_id: str, endpoint_id: str,
                       stage: str, *, evidence_gate: str) -> dict[str, Any]:
        audit_id = self._id(audit_id, "audit ID")
        group_id = self._id(group_id, "group ID")
        endpoint_id = self._id(endpoint_id, "endpoint ID")
        if stage not in {"quick_screen", "deep_agent"}:
            raise BudgetError("unsupported model stage")
        gates = {"ranked_and_selected", "quick_screen_investigate"}
        if evidence_gate not in gates:
            raise BudgetError("dispatch requires an explicit evidence gate")
        if stage == "deep_agent" and evidence_gate != "quick_screen_investigate":
            raise BudgetError("deep Agent requires a qualifying evidence gate")
        if stage == "quick_screen" and evidence_gate != "ranked_and_selected":
            raise BudgetError("quick screen requires a locally ranked selected group")
        now = self._now()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            audit = db.execute("SELECT * FROM audit_budget WHERE audit_id=?", (audit_id,)).fetchone()
            if not audit:
                db.rollback()
                raise BudgetError("audit budget snapshot not found")
            prior = db.execute(
                "SELECT * FROM triage_dispatch WHERE audit_id=? AND group_id=? AND stage=?",
                (audit_id, group_id, stage),
            ).fetchone()
            if prior:
                if prior["endpoint_id"] != endpoint_id or prior["evidence_gate"] != evidence_gate:
                    db.rollback()
                    raise BudgetConflict("group dispatch already exists with different inputs")
                db.commit()
                return dict(prior)
            policy = json.loads(audit["policy_json"])
            limits = policy["limits"]
            if audit["status"] != "active":
                db.rollback()
                raise BudgetError("audit scheduling has stopped")
            if stage == "deep_agent" and evidence_gate == "quick_screen_investigate":
                quick = db.execute(
                    "SELECT status,quick_assessment FROM triage_dispatch WHERE audit_id=? AND group_id=? AND stage='quick_screen'",
                    (audit_id, group_id),
                ).fetchone()
                if not quick or quick["status"] != "completed" or quick["quick_assessment"] != "investigate":
                    db.rollback()
                    raise BudgetError("deep Agent requires a completed investigate quick screen")
            limit_key = "quick_screen_groups_per_audit" if stage == "quick_screen" else "deep_groups_per_audit"
            count = db.execute(
                "SELECT count(*) FROM triage_dispatch WHERE audit_id=? AND stage=? AND status!='known_not_sent'",
                (audit_id, stage),
            ).fetchone()[0]
            if count >= limits[limit_key]:
                db.rollback()
                raise BudgetError(stage + " group budget exhausted")
            db.execute(
                "INSERT INTO triage_dispatch(audit_id,group_id,endpoint_id,stage,evidence_gate,quick_assessment,status,created_at) VALUES(?,?,?,?,?,NULL,?,?)",
                (audit_id, group_id, endpoint_id, stage, evidence_gate, "queued", now),
            )
            db.commit()
        return {"audit_id": audit_id, "group_id": group_id, "endpoint_id": endpoint_id,
                "stage": stage, "evidence_gate": evidence_gate, "status": "queued"}

    def claim_deep_operation(self, audit_id: str, group_id: str,
                             endpoint_id: str, operation_id: str) -> dict[str, Any]:
        """Atomically bind one L3 group to one consented operation (single flight)."""
        audit_id = self._id(audit_id, "audit ID")
        group_id = self._id(group_id, "group ID")
        endpoint_id = self._id(endpoint_id, "endpoint ID")
        operation_id = self._id(operation_id, "operation ID")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM triage_dispatch WHERE audit_id=? AND group_id=? AND stage='deep_agent'",
                (audit_id, group_id),
            ).fetchone()
            if not row or row["endpoint_id"] != endpoint_id or row["status"] not in {"queued", "running"}:
                db.rollback()
                raise BudgetError("deep Agent group cannot be claimed or replayed")
            if row["deep_operation_id"] not in (None, operation_id):
                db.rollback()
                raise BudgetConflict("deep Agent group already belongs to another operation")
            db.execute(
                "UPDATE triage_dispatch SET deep_operation_id=? WHERE audit_id=? AND group_id=? AND stage='deep_agent'",
                (operation_id, audit_id, group_id),
            )
            db.commit()
            return {**dict(row), "deep_operation_id": operation_id}

    def reserve(self, audit_id: str, idempotency_key: str, endpoint_id: str,
                group_id: str, stage: str, *, max_input_tokens: int,
                max_output_tokens: int, phase: str | None = None) -> dict[str, Any]:
        audit_id = self._id(audit_id, "audit ID")
        idempotency_key = self._id(idempotency_key, "idempotency key", 160)
        endpoint_id = self._id(endpoint_id, "endpoint ID")
        group_id = self._id(group_id, "group ID")
        if stage not in {"quick_screen", "deep_agent"}:
            raise BudgetError("unsupported model stage")
        if phase is None:
            phase = stage
        allowed_phases = {"quick_screen"} if stage == "quick_screen" else {
            "deep_agent", "structured_repair", "skeptic", "report",
        }
        if phase not in allowed_phases:
            raise BudgetError("unsupported model phase for this stage")
        for value, label in ((max_input_tokens, "input reservation"),
                             (max_output_tokens, "output reservation")):
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise BudgetError(f"{label} must be a positive integer")
        now = self._now()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            audit = db.execute("SELECT * FROM audit_budget WHERE audit_id=?", (audit_id,)).fetchone()
            if not audit:
                db.rollback()
                raise BudgetError("audit budget snapshot not found")
            prior = db.execute(
                "SELECT * FROM budget_reservation WHERE audit_id=? AND idempotency_key=?",
                (audit_id, idempotency_key),
            ).fetchone()
            identity = (endpoint_id, group_id, stage, phase, max_input_tokens, max_output_tokens)
            if prior:
                prior_identity = (prior["endpoint_id"], prior["group_id"], prior["stage"],
                                  prior["phase"], prior["max_input_tokens"], prior["max_output_tokens"])
                if prior_identity != identity:
                    db.rollback()
                    raise BudgetConflict("idempotency key reused with different reservation inputs")
                db.commit()
                return {**dict(prior), "idempotent_replay": True}
            policy = json.loads(audit["policy_json"])
            limits = policy["limits"]
            if audit["status"] != "active":
                db.rollback()
                raise BudgetError("audit scheduling has stopped")
            dispatch = db.execute(
                "SELECT status FROM triage_dispatch WHERE audit_id=? AND group_id=? AND stage=? AND endpoint_id=?",
                (audit_id, group_id, stage, endpoint_id),
            ).fetchone()
            if not dispatch or dispatch["status"] not in {"queued", "running"}:
                db.rollback()
                raise BudgetError("group is not queued for this model stage")
            # Deep Agent tool-step limits are enforced by the existing Agent
            # loop's max_steps. Reservations here count model requests, including
            # repairs, Skeptic, and report stages, against the shared task budget.
            inflight = db.execute(
                "SELECT count(*) FROM budget_reservation WHERE audit_id=? AND status='reserved'",
                (audit_id,),
            ).fetchone()[0]
            if inflight >= limits["max_model_concurrency"]:
                db.rollback()
                raise BudgetError("model concurrency budget exhausted")
            reservation_id = uuid.uuid4().hex
            db.execute(
                "INSERT INTO budget_reservation(reservation_id,audit_id,idempotency_key,endpoint_id,group_id,stage,phase,max_input_tokens,max_output_tokens,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (reservation_id, audit_id, idempotency_key, endpoint_id, group_id, stage, phase,
                 max_input_tokens, max_output_tokens, "reserved", now),
            )
            db.execute(
                "UPDATE triage_dispatch SET status='running' WHERE audit_id=? AND group_id=? AND stage=?",
                (audit_id, group_id, stage),
            )
            db.commit()
        return {"reservation_id": reservation_id, "audit_id": audit_id,
                "endpoint_id": endpoint_id, "group_id": group_id, "stage": stage, "phase": phase,
                "max_input_tokens": max_input_tokens, "max_output_tokens": max_output_tokens,
                "status": "reserved", "idempotent_replay": False}

    def settle(self, reservation_id: str, *, outcome: str,
               input_tokens: int | None = None, output_tokens: int | None = None,
               quick_assessment: str | None = None,
               estimated_cost_usd: str | None = None) -> dict[str, Any]:
        reservation_id = self._id(reservation_id, "reservation ID")
        if outcome not in {"completed", "known_not_sent", "unknown_outcome"}:
            raise BudgetError("unsupported settlement outcome")
        if estimated_cost_usd is not None:
            if not isinstance(estimated_cost_usd, str):
                raise BudgetError("estimated cost must be a decimal string")
            try:
                cost = Decimal(estimated_cost_usd)
            except InvalidOperation as error:
                raise BudgetError("estimated cost is invalid") from error
            if not cost.is_finite() or cost < 0:
                raise BudgetError("estimated cost must be non-negative")
            estimated_cost_usd = format(cost, "f")
        if outcome == "completed":
            usage_ok = (
                isinstance(input_tokens, int) and not isinstance(input_tokens, bool) and input_tokens >= 0
                and isinstance(output_tokens, int) and not isinstance(output_tokens, bool) and output_tokens >= 0
            )
            if not usage_ok:
                outcome = "unknown_outcome"
        now = self._now()
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM budget_reservation WHERE reservation_id=?",
                             (reservation_id,)).fetchone()
            if not row:
                db.rollback()
                raise BudgetError("budget reservation not found")
            if row["status"] != "reserved":
                db.commit()
                return dict(row)
            if outcome == "completed" and row["stage"] == "quick_screen" and quick_assessment not in {
                "investigate", "defer", "possible_refutation", "insufficient_context",
            }:
                outcome = "unknown_outcome"
            if outcome == "known_not_sent":
                status, actual_in, actual_out = "known_not_sent", 0, 0
            elif outcome == "unknown_outcome":
                # Keep full pre-call reservation: an ambiguous response may have been billed.
                status, actual_in, actual_out = "unknown_outcome", None, None
            else:
                # Reservations are estimates for usage reporting only. Provider
                # usage may exceed an estimate and must never stop an authorized
                # investigation. Missing usage remains unknown while the call
                # itself is still completed.
                status, actual_in, actual_out = "completed", input_tokens, output_tokens
            db.execute(
                "UPDATE budget_reservation SET status=?,actual_input_tokens=?,actual_output_tokens=?,estimated_cost_usd=?,finished_at=? WHERE reservation_id=?",
                (status, actual_in, actual_out, estimated_cost_usd, now, reservation_id),
            )
            # A successful L3 Provider call is NOT completion of the
            # multi-request Agent/Skeptic/report workflow. Keep its group
            # running so the next separately reserved call can proceed.
            if row["stage"] == "deep_agent":
                dispatch_status = "running" if status == "completed" else "partial"
            else:
                dispatch_status = ("partial" if status in {"unknown_outcome", "budget_violation"}
                                   else "completed" if status == "completed" else "known_not_sent")
            db.execute(
                "UPDATE triage_dispatch SET status=?,quick_assessment=? WHERE audit_id=? AND group_id=? AND stage=?",
                (dispatch_status, quick_assessment if row["stage"] == "quick_screen" and status == "completed" else None,
                 row["audit_id"], row["group_id"], row["stage"]),
            )
            db.commit()
        return self.reservation(reservation_id)

    def finish_deep_group(self, audit_id: str, group_id: str, endpoint_id: str,
                          operation_id: str, *, success: bool) -> dict[str, Any]:
        """Finalise L3 only after the *whole* investigation returns."""
        audit_id = self._id(audit_id, "audit ID")
        group_id = self._id(group_id, "group ID")
        endpoint_id = self._id(endpoint_id, "endpoint ID")
        operation_id = self._id(operation_id, "operation ID")
        if not isinstance(success, bool):
            raise BudgetError("deep Agent final status must be boolean")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM triage_dispatch WHERE audit_id=? AND group_id=? AND stage='deep_agent'",
                (audit_id, group_id),
            ).fetchone()
            if (not row or row["endpoint_id"] != endpoint_id
                    or row["deep_operation_id"] != operation_id):
                db.rollback()
                raise BudgetConflict("deep Agent final status has an invalid operation owner")
            if row["status"] == "completed" and success:
                db.commit()
                return dict(row)
            if row["status"] not in {"queued", "running"}:
                db.rollback()
                raise BudgetError("deep Agent cannot change a terminal or partial group")
            if success:
                statuses = [item[0] for item in db.execute(
                    "SELECT status FROM budget_reservation WHERE audit_id=? AND group_id=? AND endpoint_id=? AND stage='deep_agent'",
                    (audit_id, group_id, endpoint_id),
                )]
                if not statuses or "completed" not in statuses or any(
                        status != "completed" for status in statuses):
                    db.rollback()
                    raise BudgetError("deep Agent has incomplete or unknown Provider reservations")
            next_status = "completed" if success else "partial"
            db.execute(
                "UPDATE triage_dispatch SET status=? WHERE audit_id=? AND group_id=? AND stage='deep_agent'",
                (next_status, audit_id, group_id),
            )
            db.commit()
        return {**dict(row), "status": next_status}

    def stop(self, audit_id: str, reason: str) -> dict[str, Any]:
        audit_id = self._id(audit_id, "audit ID")
        allowed = {"no_progress", "evidence_complete", "budget_exhausted",
                   "time_budget_exhausted", "cancelled", "authorization_revoked",
                   "source_scope_denied", "partial_unknown"}
        if reason not in allowed:
            raise BudgetError("unsupported stop reason")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM audit_budget WHERE audit_id=?", (audit_id,)).fetchone():
                db.rollback()
                raise BudgetError("audit budget snapshot not found")
            db.execute("UPDATE audit_budget SET status='stopped',stop_reason=? WHERE audit_id=?",
                       (reason, audit_id))
            db.commit()
        return self.get(audit_id)

    def reservation(self, reservation_id: str) -> dict[str, Any]:
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM budget_reservation WHERE reservation_id=?",
                             (reservation_id,)).fetchone()
        if not row:
            raise BudgetError("budget reservation not found")
        return dict(row)

    def get(self, audit_id: str) -> dict[str, Any]:
        audit_id = self._id(audit_id, "audit ID")
        with closing(self._connect()) as db:
            audit = db.execute("SELECT * FROM audit_budget WHERE audit_id=?", (audit_id,)).fetchone()
            if not audit:
                raise BudgetError("audit budget snapshot not found")
            reservations = db.execute(
                "SELECT stage,phase,status,max_input_tokens,max_output_tokens,actual_input_tokens,actual_output_tokens FROM budget_reservation WHERE audit_id=?",
                (audit_id,),
            ).fetchall()
            dispatches = db.execute(
                "SELECT stage,status FROM triage_dispatch WHERE audit_id=?", (audit_id,)
            ).fetchall()
        policy = json.loads(audit["policy_json"])
        limits = policy["limits"]
        calls = used_in = used_out = inflight = 0
        usage_by_phase = {}
        for row in reservations:
            phase = row["phase"] or ("quick_screen" if row["stage"] == "quick_screen" else "deep_agent")
            phase_usage = usage_by_phase.setdefault(phase, {
                "model_calls_allocated": 0, "model_calls_in_flight": 0,
                "model_calls_completed": 0, "model_calls_unknown": 0,
                "input_tokens_allocated": 0, "output_tokens_allocated": 0,
            })
            if row["status"] == "known_not_sent":
                continue
            calls += 1
            inflight += int(row["status"] == "reserved")
            input_tokens = row["actual_input_tokens"] if row["actual_input_tokens"] is not None else row["max_input_tokens"]
            output_tokens = row["actual_output_tokens"] if row["actual_output_tokens"] is not None else row["max_output_tokens"]
            used_in += input_tokens
            used_out += output_tokens
            phase_usage["model_calls_allocated"] += 1
            phase_usage["model_calls_in_flight"] += int(row["status"] == "reserved")
            phase_usage["model_calls_completed"] += int(row["status"] == "completed")
            phase_usage["model_calls_unknown"] += int(row["status"] in {"unknown_outcome", "budget_violation"})
            phase_usage["input_tokens_allocated"] += input_tokens
            phase_usage["output_tokens_allocated"] += output_tokens
        elapsed = max(0, int(self._now() - audit["created_at"]))
        return {
            "audit_id": audit_id, "policy_sha256": audit["policy_sha256"],
            "status": audit["status"], "stop_reason": audit["stop_reason"],
            "phase_counts": {
                "quick_screen_groups": sum(1 for row in dispatches if row["stage"] == "quick_screen" and row["status"] != "known_not_sent"),
                "deep_agent_groups": sum(1 for row in dispatches if row["stage"] == "deep_agent" and row["status"] != "known_not_sent"),
            },
            "usage": {
                "model_calls_allocated": calls, "model_calls_in_flight": inflight,
                "input_tokens_allocated": used_in, "output_tokens_allocated": used_out,
                "wall_seconds_elapsed": elapsed,
                "wall_seconds_remaining": None,
                "max_model_calls": None,
                "max_input_tokens": None,
                "max_output_tokens": None,
                "cumulative_usage_limits_enforced": False,
                "by_phase": usage_by_phase,
            },
            "cost": {
                "policy_max_cost_usd": limits["max_cost_usd"],
                "enforcement": audit["cost_enforcement"],
                "actual_usd": None, "estimated_usd": None,
            },
            "unassessed_groups_remain_candidates": True, "validated_vulnerability": 0,
        }
