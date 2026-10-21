"""Incremental operation queue; old scan artifacts and identities stay untouched."""
import fcntl
import hashlib
import json
from pathlib import Path
import sqlite3
import statistics
import uuid
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation
from .store import now
from .triage_limits import (MAX_TRIAGE_CANDIDATES_PER_ENDPOINT,
                            MAX_AUTHORIZED_TRIAGE_QUEUE_ITEMS)

END = {"completed", "completed_with_limitations", "blocked", "failed", "cancelled", "timed_out", "interrupted"}


class Operations:
    def __init__(self, store):
        self.store = store
        with (store.root / "migration.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with store.connect() as db:
                version = db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
            if version < 3:
                backups = store.root / "backups"
                backups.mkdir(exist_ok=True)
                with sqlite3.connect(store.path) as src, sqlite3.connect(backups / ("before-v3-" + uuid.uuid4().hex + ".sqlite3")) as dst:
                    src.backup(dst)
                with store.connect() as db:
                    db.executescript("""
                    CREATE TABLE IF NOT EXISTS operations(
                      id TEXT PRIMARY KEY, kind TEXT NOT NULL, spec TEXT NOT NULL,
                      status TEXT NOT NULL, created_at TEXT NOT NULL, started_at TEXT,
                      finished_at TEXT, cancel_requested INTEGER NOT NULL DEFAULT 0,
                      result_sha256 TEXT, error TEXT);
                    CREATE TABLE IF NOT EXISTS operation_events(
                      id INTEGER PRIMARY KEY AUTOINCREMENT, operation_id TEXT NOT NULL REFERENCES operations(id),
                      created_at TEXT NOT NULL, stage TEXT NOT NULL, message TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS case_assessments(
                      id INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL REFERENCES cases(id),
                      record TEXT NOT NULL, created_at TEXT NOT NULL);
                    INSERT OR IGNORE INTO schema_migrations VALUES(3);
                    """)

            with store.connect() as db:
                current_version = db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
            if current_version < 4:
                backups = store.root / "backups"
                backups.mkdir(exist_ok=True)
                with sqlite3.connect(store.path) as src, sqlite3.connect(backups / ("before-v4-" + uuid.uuid4().hex + ".sqlite3")) as dst:
                    src.backup(dst)
                with store.connect() as db:
                    db.executescript("""
                    CREATE TABLE IF NOT EXISTS agent_baseline_reviews(
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      experiment_id TEXT NOT NULL,
                      repository TEXT NOT NULL,
                      source_commit TEXT NOT NULL,
                      job_id TEXT NOT NULL,
                      candidate_id TEXT NOT NULL,
                      record TEXT NOT NULL,
                      record_sha256 TEXT NOT NULL,
                      created_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS agent_baseline_pair
                      ON agent_baseline_reviews(experiment_id,repository,source_commit,candidate_id);
                    INSERT OR IGNORE INTO schema_migrations VALUES(4);
                    """)
        with (store.root / "migration.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with store.connect() as db:
                current_version = db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
            if current_version < 5:
                backups = store.root / "backups"
                backups.mkdir(exist_ok=True)
                with sqlite3.connect(store.path) as src, sqlite3.connect(backups / ("before-v5-" + uuid.uuid4().hex + ".sqlite3")) as dst:
                    src.backup(dst)
                with store.connect() as db:
                    db.executescript("""
                    CREATE TABLE IF NOT EXISTS agent_blind_sessions(
                      id TEXT PRIMARY KEY,
                      experiment_id TEXT NOT NULL,
                      state TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      closed_at TEXT
                    );
                    CREATE TABLE IF NOT EXISTS agent_blind_items(
                      id TEXT PRIMARY KEY,
                      session_id TEXT NOT NULL REFERENCES agent_blind_sessions(id),
                      operation_id TEXT NOT NULL REFERENCES operations(id),
                      result_sha256 TEXT NOT NULL,
                      item_order INTEGER NOT NULL,
                      packet TEXT NOT NULL,
                      packet_sha256 TEXT NOT NULL,
                      UNIQUE(session_id, operation_id),
                      UNIQUE(session_id, item_order)
                    );
                    CREATE TABLE IF NOT EXISTS agent_blind_reviews(
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      session_id TEXT NOT NULL REFERENCES agent_blind_sessions(id),
                      item_id TEXT NOT NULL REFERENCES agent_blind_items(id),
                      result_sha256 TEXT NOT NULL,
                      record TEXT NOT NULL,
                      record_sha256 TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      UNIQUE(session_id, item_id)
                    );
                    CREATE INDEX IF NOT EXISTS agent_blind_item_session_order
                      ON agent_blind_items(session_id,item_order);
                    INSERT OR IGNORE INTO schema_migrations VALUES(5);
                    """)
            with store.connect() as db:
                current_version = db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
            if current_version < 6:
                backups = store.root / "backups"
                backups.mkdir(exist_ok=True)
                with sqlite3.connect(store.path) as src, sqlite3.connect(backups / ("before-v6-" + uuid.uuid4().hex + ".sqlite3")) as dst:
                    src.backup(dst)
                with store.connect() as db:
                    db.executescript("""
                    CREATE TABLE IF NOT EXISTS triage_authorizations(
                      audit_id TEXT PRIMARY KEY REFERENCES jobs(id),
                      consent_sha256 TEXT NOT NULL,
                      snapshot TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      revoked_at TEXT
                    );
                    CREATE TABLE IF NOT EXISTS smart_triage_batches(
                      id TEXT PRIMARY KEY,
                      audit_id TEXT NOT NULL REFERENCES jobs(id),
                      report_sha256 TEXT NOT NULL,
                      authorization_sha256 TEXT NOT NULL,
                      batch_consent_sha256 TEXT NOT NULL,
                      status TEXT NOT NULL,
                      candidate_count INTEGER NOT NULL,
                      selected_count INTEGER NOT NULL,
                      candidate_manifest TEXT NOT NULL,
                      operation_ids TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      error TEXT,
                      UNIQUE(audit_id,report_sha256,authorization_sha256)
                    );
                    CREATE INDEX IF NOT EXISTS smart_triage_audit_order
                      ON smart_triage_batches(audit_id,created_at);
                    INSERT OR IGNORE INTO schema_migrations VALUES(6);
                    """)
            with store.connect() as db:
                current_version = db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
            if current_version < 7:
                backups = store.root / "backups"
                backups.mkdir(exist_ok=True)
                with sqlite3.connect(store.path) as src, sqlite3.connect(backups / ("before-v7-" + uuid.uuid4().hex + ".sqlite3")) as dst:
                    src.backup(dst)
                with store.connect() as db:
                    db.executescript("""
                    CREATE TABLE IF NOT EXISTS risk_snapshots(
                      id TEXT PRIMARY KEY,
                      audit_id TEXT NOT NULL REFERENCES jobs(id),
                      report_sha256 TEXT NOT NULL,
                      content_sha256 TEXT NOT NULL,
                      policy_version TEXT NOT NULL,
                      content TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      UNIQUE(audit_id,report_sha256,content_sha256)
                    );
                    CREATE INDEX IF NOT EXISTS risk_snapshot_audit_order
                      ON risk_snapshots(audit_id,created_at);
                    CREATE TABLE IF NOT EXISTS report_snapshots(
                      id TEXT PRIMARY KEY,
                      audit_id TEXT NOT NULL REFERENCES jobs(id),
                      report_sha256 TEXT NOT NULL,
                      risk_snapshot_id TEXT NOT NULL REFERENCES risk_snapshots(id),
                      content_sha256 TEXT NOT NULL,
                      json_sha256 TEXT NOT NULL,
                      markdown_sha256 TEXT NOT NULL,
                      json_content TEXT NOT NULL,
                      markdown_content TEXT NOT NULL,
                      created_at TEXT NOT NULL,
                      UNIQUE(audit_id,report_sha256,content_sha256)
                    );
                    CREATE INDEX IF NOT EXISTS report_snapshot_audit_order
                      ON report_snapshots(audit_id,created_at);
                    INSERT OR IGNORE INTO schema_migrations VALUES(7);
                    """)
            with store.connect() as db:
                current_version = db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
            if current_version < 8:
                backups = store.root / "backups"
                backups.mkdir(exist_ok=True)
                with sqlite3.connect(store.path) as src, sqlite3.connect(backups / ("before-v8-" + uuid.uuid4().hex + ".sqlite3")) as dst:
                    src.backup(dst)
                with store.connect() as db:
                    db.executescript("""
                    ALTER TABLE smart_triage_batches ADD COLUMN r2_status TEXT NOT NULL DEFAULT 'not_requested';
                    ALTER TABLE smart_triage_batches ADD COLUMN r2_operation_ids TEXT NOT NULL DEFAULT '[]';
                    ALTER TABLE smart_triage_batches ADD COLUMN r2_candidate_manifest TEXT NOT NULL DEFAULT '[]';
                    ALTER TABLE smart_triage_batches ADD COLUMN r2_decision_sha256 TEXT;
                    ALTER TABLE smart_triage_batches ADD COLUMN r2_error TEXT;
                    INSERT OR IGNORE INTO schema_migrations VALUES(8);
                    """)
            with store.connect() as db:
                current_version = db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
            if current_version < 9:
                backups = store.root / "backups"
                backups.mkdir(exist_ok=True)
                with sqlite3.connect(store.path) as src, sqlite3.connect(backups / ("before-v9-" + uuid.uuid4().hex + ".sqlite3")) as dst:
                    src.backup(dst)
                with store.connect() as db:
                    db.executescript("""
                    CREATE TABLE IF NOT EXISTS triage_cancellations(
                      audit_id TEXT PRIMARY KEY REFERENCES jobs(id),
                      report_sha256 TEXT,
                      created_at TEXT NOT NULL
                    );
                    INSERT OR IGNORE INTO schema_migrations VALUES(9);
                    """)
            with store.connect() as db:
                current_version = db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
            if current_version < 10:
                backups = store.root / "backups"
                backups.mkdir(exist_ok=True)
                with sqlite3.connect(store.path) as src, sqlite3.connect(backups / ("before-v10-" + uuid.uuid4().hex + ".sqlite3")) as dst:
                    src.backup(dst)
                with store.connect() as db:
                    db.executescript("""
                    CREATE TABLE IF NOT EXISTS operation_cancellations(
                      operation_id TEXT PRIMARY KEY REFERENCES operations(id),
                      requested_at TEXT NOT NULL,
                      reason TEXT NOT NULL
                    );
                    INSERT OR IGNORE INTO schema_migrations VALUES(10);
                    """)
            with store.connect() as db:
                current_version = db.execute("SELECT max(version) FROM schema_migrations").fetchone()[0]
            if current_version < 11:
                backups = store.root / "backups"
                backups.mkdir(exist_ok=True)
                with sqlite3.connect(store.path) as src, sqlite3.connect(backups / ("before-v11-" + uuid.uuid4().hex + ".sqlite3")) as dst:
                    src.backup(dst)
                with store.connect() as db:
                    db.executescript("""
                    CREATE TABLE IF NOT EXISTS joint_comparison_preview_tickets(
                      consent_nonce TEXT PRIMARY KEY,
                      consent_sha256 TEXT NOT NULL,
                      expires_at TEXT NOT NULL,
                      issued_at TEXT NOT NULL,
                      consumed_by TEXT REFERENCES operations(id),
                      consumed_at TEXT
                    );
                    CREATE INDEX IF NOT EXISTS joint_comparison_ticket_expiry
                      ON joint_comparison_preview_tickets(expires_at,consumed_by);
                    INSERT OR IGNORE INTO schema_migrations VALUES(11);
                    """)
    def directory(self, key):
        if len(key) != 32 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("invalid operation ID")
        return self.store.root / "operations" / key

    def issue_joint_comparison_preview_ticket(self, consent_nonce, consent_sha256, expires_at):
        """Persist a short-lived, one-use approval binding created by a preview."""
        if (not isinstance(consent_nonce, str) or len(consent_nonce) != 32
                or any(ch not in "0123456789abcdef" for ch in consent_nonce)
                or not isinstance(consent_sha256, str) or len(consent_sha256) != 64
                or any(ch not in "0123456789abcdef" for ch in consent_sha256)):
            raise ValueError("joint comparison preview ticket binding is invalid")
        try:
            expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except (TypeError, ValueError, AttributeError):
            raise ValueError("joint comparison preview ticket expiry is invalid") from None
        if expiry.tzinfo is None or expiry <= datetime.now(expiry.tzinfo):
            raise ValueError("joint comparison preview ticket has expired")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM joint_comparison_preview_tickets WHERE consumed_by IS NULL AND expires_at<=?",
                       (datetime.now(expiry.tzinfo).isoformat(timespec="seconds"),))
            active = db.execute("SELECT count(*) FROM joint_comparison_preview_tickets WHERE consumed_by IS NULL").fetchone()[0]
            if active >= 512:
                raise ValueError("too many unused joint comparison previews; wait for older previews to expire")
            try:
                db.execute("INSERT INTO joint_comparison_preview_tickets(consent_nonce,consent_sha256,expires_at,issued_at) VALUES(?,?,?,?)",
                           (consent_nonce, consent_sha256, expiry.isoformat(timespec="seconds"), now()))
            except sqlite3.IntegrityError:
                raise ValueError("joint comparison preview ticket nonce already exists") from None

    def joint_comparison_ticket_allows_worker(self, operation_id, consent_nonce, consent_sha256):
        with self.store.connect() as db:
            row = db.execute("SELECT consumed_by,consent_sha256 FROM joint_comparison_preview_tickets WHERE consent_nonce=?",
                             (consent_nonce,)).fetchone()
        return bool(row and row["consumed_by"] == operation_id
                    and row["consent_sha256"] == consent_sha256)

    def create(self, kind, spec):
        if kind not in {"source_sync", "source_sync_batch", "repository_import_scan", "revision_range", "version_matrix", "branch_comparison", "recent_window_comparison", "validation", "investigation", "candidate_review_batch", "agent_investigation", "version_candidate_comparison", "progressive_quick_screen"}:
            raise ValueError("unknown operation kind")
        if kind == "progressive_quick_screen":
            from .progressive_triage.contracts import SHA256_RE, content_sha256
            required = ("consent_nonce", "consent_sha256", "job_id", "candidate_id",
                        "consent_manifest", "group", "evidence", "authorization")
            if (not isinstance(spec, dict)
                    or spec.get("source_submission_approved") is not True
                    or any(not isinstance(spec.get(name), str) or not spec[name]
                           for name in required[:4])
                    or not isinstance(spec.get("consent_manifest"), dict)
                    or not isinstance(spec.get("group"), dict)
                    or not isinstance(spec.get("evidence"), list)
                    or not isinstance(spec.get("authorization"), dict)
                    or not isinstance(spec.get("progressive_policy"), dict)
                    or not isinstance(spec.get("ranking"), dict)
                    or not isinstance(spec.get("audit_operation_id"), str)
                    or spec["consent_manifest"].get("audit_operation_id") != spec.get("audit_operation_id")
                    or not SHA256_RE.fullmatch(spec["consent_sha256"])
                    or len(spec["consent_nonce"]) != 32
                    or any(ch not in "0123456789abcdef" for ch in spec["consent_nonce"])
                    or content_sha256(spec["consent_manifest"]) != spec["consent_sha256"]
                    or spec["consent_manifest"].get("group") != spec["group"]
                    or spec["consent_manifest"].get("evidence") != spec["evidence"]
                    or spec["consent_manifest"].get("ranking") != spec["ranking"]
                    or spec["consent_manifest"].get("policy") != spec["progressive_policy"].get("policy")
                    or spec["consent_manifest"].get("policy_sha256") != spec["progressive_policy"].get("policy_sha256")
                    or spec["consent_manifest"].get("policy_revision") != spec["progressive_policy"].get("revision")
                    or spec["authorization"].get("consent_sha256") != spec["consent_sha256"]):
                raise ValueError("progressive quick screen requires a fixed, explicit consent binding")
            try:
                expiry = datetime.fromisoformat(spec.get("consent_expires_at", "").replace("Z", "+00:00"))
            except (AttributeError, TypeError, ValueError):
                raise ValueError("progressive quick screen consent expiry is invalid") from None
            if (expiry.tzinfo is None or expiry <= datetime.now(timezone.utc)
                    or spec["consent_manifest"].get("consent_expires_at") != spec["consent_expires_at"]):
                raise ValueError("progressive quick screen consent has expired or changed")
        if kind == "version_candidate_comparison":
            required = ("from_commit", "from_candidate_id", "to_commit", "to_candidate_id",
                        "consent_nonce", "consent_sha256", "consent_expires_at",
                        "provider_fingerprint", "joint_context_sha256", "joint_binding_snapshot")
            parent_ids = ("matrix_operation_id", "recent_window_operation_id")
            selected_parent_ids = ([name for name in parent_ids
                                    if isinstance(spec.get(name), str) and spec[name]]
                                   if isinstance(spec, dict) else [])
            if (not isinstance(spec, dict)
                    or spec.get("source_submission_approved") is not True
                    or len(selected_parent_ids) != 1
                    or any(len(spec[name]) != 32
                           or any(ch not in "0123456789abcdef" for ch in spec[name])
                           for name in selected_parent_ids)
                    or any(not isinstance(spec.get(name), str) or not spec[name] for name in required[:-1])
                    or not isinstance(spec.get("joint_binding_snapshot"), dict)
                    or len(spec["consent_nonce"]) != 32
                    or any(ch not in "0123456789abcdef" for ch in spec["consent_nonce"])
                    or any(len(spec[name]) != 64 or any(ch not in "0123456789abcdef" for ch in spec[name])
                           for name in ("consent_sha256", "provider_fingerprint", "joint_context_sha256"))):
                raise ValueError("joint version comparison requires a complete explicit consent binding")
            try:
                expiry = datetime.fromisoformat(spec["consent_expires_at"].replace("Z", "+00:00"))
            except (TypeError, ValueError, AttributeError):
                raise ValueError("joint version comparison consent expiry is invalid") from None
            if expiry.tzinfo is None or expiry <= datetime.now(expiry.tzinfo):
                raise ValueError("joint version comparison consent has expired")
        key = uuid.uuid4().hex
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if kind == "candidate_review_batch":
                # One immutable batch points at every finding in one fixed report. Keep it
                # queued under load instead of rejecting/truncating the candidate set.
                prior = db.execute("SELECT id FROM operations WHERE kind=? AND spec=? AND status IN ('queued','running','completed','completed_with_limitations') ORDER BY created_at DESC LIMIT 1",
                                   (kind, json.dumps(spec, sort_keys=True))).fetchone()
                if prior:
                    return self.row(db.execute("SELECT * FROM operations WHERE id=?", (prior[0],)).fetchone())
            elif kind == "version_candidate_comparison":
                ticket = db.execute("SELECT * FROM joint_comparison_preview_tickets WHERE consent_nonce=?",
                                    (spec["consent_nonce"],)).fetchone()
                if (not ticket or ticket["consent_sha256"] != spec["consent_sha256"]
                        or ticket["expires_at"] != spec["consent_expires_at"]):
                    raise ValueError("joint comparison approval ticket is missing or does not match this preview")
                expiry = datetime.fromisoformat(ticket["expires_at"].replace("Z", "+00:00"))
                if expiry.tzinfo is None or expiry <= datetime.now(expiry.tzinfo):
                    raise ValueError("joint comparison approval ticket has expired")
                if ticket["consumed_by"]:
                    prior = db.execute("SELECT * FROM operations WHERE id=? AND kind=?",
                                       (ticket["consumed_by"], kind)).fetchone()
                    if prior and json.loads(prior["spec"]).get("consent_sha256") == spec["consent_sha256"]:
                        return self.row(prior)
                    raise ValueError("joint comparison approval ticket has already been used")
            elif kind == "agent_investigation" and spec.get("progressive_consent_sha256"):
                for row in db.execute("SELECT * FROM operations WHERE kind=?", (kind,)):
                    existing_spec = json.loads(row["spec"])
                    if (existing_spec.get("progressive_consent_sha256") == spec["progressive_consent_sha256"]
                            and existing_spec.get("source_consent_sha256") == spec.get("source_consent_sha256")):
                        return self.row(row)
            elif kind == "agent_investigation" and spec.get("source_consent_sha256"):
                # Consent hashes include a fresh preview nonce. A network/client retry with
                # the same explicit approval must return the original operation, avoiding
                # duplicate model calls and charges. A new preview is a deliberate rerun.
                for row in db.execute("SELECT * FROM operations WHERE kind=?", (kind,)):
                    existing_spec = json.loads(row["spec"])
                    if existing_spec.get("source_consent_sha256") == spec["source_consent_sha256"]:
                        return self.row(row)
            elif kind == "progressive_quick_screen":
                # A repeated submission of one approval returns the recorded operation;
                # it cannot create a second billable request.
                audit_operation_id = spec["audit_operation_id"]
                if audit_operation_id != spec["job_id"]:
                    parent_row = db.execute("SELECT kind,spec,status,cancel_requested FROM operations WHERE id=?",
                                            (audit_operation_id,)).fetchone()
                    if not parent_row or parent_row["kind"] not in {
                            "revision_range", "version_matrix", "branch_comparison", "recent_window_comparison"}:
                        raise ValueError("progressive quick screen parent audit does not exist")
                    parent_spec = json.loads(parent_row["spec"])
                    if (spec["job_id"] not in parent_spec.get("scan_ids", [])
                            or parent_spec.get("progressive_triage_policy") != spec["progressive_policy"]
                            or parent_spec.get("audit_mode") == "static_only"
                            or parent_row["cancel_requested"]
                            or parent_row["status"] in {"cancelled", "failed", "timed_out", "interrupted"}):
                        raise ValueError("progressive quick screen is not bound to its frozen intelligent audit")
                for row in db.execute("SELECT * FROM operations WHERE kind=?", (kind,)):
                    existing_spec = json.loads(row["spec"])
                    if existing_spec.get("consent_sha256") == spec["consent_sha256"]:
                        return self.row(row)
            if kind == "repository_import_scan":
                prior = db.execute("SELECT id FROM operations WHERE kind=? AND spec=? AND status IN ('queued','running') ORDER BY created_at DESC LIMIT 1",
                                   (kind, json.dumps(spec, sort_keys=True))).fetchone()
                if prior:
                    return self.row(db.execute("SELECT * FROM operations WHERE id=?", (prior[0],)).fetchone())
            if kind != "candidate_review_batch" and db.execute("SELECT count(*) FROM operations WHERE status IN ('queued','running') AND kind!='candidate_review_batch'").fetchone()[0] >= 100:
                raise ValueError("operation queue full")
            db.execute("INSERT INTO operations(id,kind,spec,status,created_at) VALUES(?,?,?,?,?)",
                       (key, kind, json.dumps(spec, sort_keys=True), "queued", now()))
            if kind == "version_candidate_comparison":
                changed = db.execute("UPDATE joint_comparison_preview_tickets SET consumed_by=?,consumed_at=? WHERE consent_nonce=? AND consent_sha256=? AND consumed_by IS NULL",
                                     (key, now(), spec["consent_nonce"], spec["consent_sha256"])).rowcount
                if changed != 1:
                    raise ValueError("joint comparison approval ticket could not be consumed")
        self.event(key, "queued", "Immutable operation plan saved")
        return self.get(key)

    def create_agent_batch(self, specs):
        """Atomically queue a small, explicitly approved set of candidate reviews."""
        if not specs or len(specs) > 5:
            raise ValueError("Agent batch must contain between one and five candidates")
        keys = [uuid.uuid4().hex for _ in specs]
        stamp = now()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing_rows = list(db.execute(
                "SELECT * FROM operations WHERE kind='agent_investigation'"))
            existing = [{"id": row["id"], "status": row["status"],
                         "spec": json.loads(row["spec"]), "db_row": row} for row in existing_rows]
            # Replaying a batch/pair approval returns the complete original group. A
            # partial match indicates corrupted/incomplete group state and must fail closed.
            group_field = "batch_consent_sha256" if specs[0].get("batch_consent_sha256") else "pair_consent_sha256"
            group_consent = specs[0].get(group_field)
            if group_consent:
                if any(spec.get(group_field) != group_consent for spec in specs):
                    raise ValueError("Agent operation group has inconsistent consent bindings")
                matched = [row for row in existing if row["spec"].get(group_field) == group_consent]
                if matched:
                    expected = sorted((spec.get("source_consent_sha256"), spec.get("batch_index", spec.get("pair_index"))) for spec in specs)
                    actual = sorted((row["spec"].get("source_consent_sha256"), row["spec"].get("batch_index", row["spec"].get("pair_index"))) for row in matched)
                    if len(matched) != len(specs) or actual != expected:
                        raise ValueError("existing Agent operation group is incomplete or conflicts with this consent")
                    return [self.row(row["db_row"]) for row in sorted(matched, key=lambda row: row["spec"].get("batch_index", row["spec"].get("pair_index", 0)))]
            active = db.execute("SELECT count(*) FROM operations WHERE status IN ('queued','running') AND kind!='candidate_review_batch'").fetchone()[0]
            if active + len(specs) > 100:
                raise ValueError("operation queue full")
            reserved = set()
            for spec in specs:
                experiment_id = spec.get("experiment_id")
                if not experiment_id:
                    continue
                identity = (experiment_id, spec.get("job_id"), spec.get("candidate_id"), spec.get("mode"))
                prior = [row for row in existing if (
                    row["spec"].get("experiment_id"), row["spec"].get("job_id"),
                    row["spec"].get("candidate_id"), row["spec"].get("mode")) == identity]
                if identity in reserved:
                    raise ValueError("an Agent result already exists for this experiment candidate arm; use a new experiment ID to rerun")
                for row in prior:
                    old_pair_id = row["spec"].get("pair_id")
                    old_pair = [item for item in existing if item["spec"].get("pair_id") == old_pair_id]
                    retryable = (row["status"] == "failed" and old_pair_id
                                 and row["spec"].get("pair_count") == 2 and len(old_pair) == 2
                                 and all(item["status"] == "failed" for item in old_pair))
                    if not retryable:
                        raise ValueError("an Agent result already exists for this experiment candidate arm; use a new experiment ID to rerun")
                reserved.add(identity)
            for key, spec in zip(keys, specs):
                db.execute("INSERT INTO operations(id,kind,spec,status,created_at) VALUES(?,?,?,?,?)",
                           (key, "agent_investigation", json.dumps(spec, sort_keys=True), "queued", stamp))
                db.execute("INSERT INTO operation_events(operation_id,created_at,stage,message) VALUES(?,?,?,?)",
                           (key, stamp, "queued", "Explicitly approved Agent batch item saved atomically"))
        return [self.get(key) for key in keys]

    @staticmethod
    def triage_batch_row(row):
        if row is None:
            raise KeyError("triage batch not found")
        item = dict(row)
        item["candidate_manifest"] = json.loads(item["candidate_manifest"])
        item["operation_ids"] = json.loads(item["operation_ids"])
        item["r2_operation_ids"] = json.loads(item.get("r2_operation_ids") or "[]")
        item["r2_candidate_manifest"] = json.loads(item.get("r2_candidate_manifest") or "[]")
        # Normalize the legacy label without rewriting historical operation rows.
        if item.get("r2_status") == "budget_limited":
            item["r2_status"] = "candidate_limit_reached"
        return item

    def record_triage_batch(self, record):
        batch_id = record.get("id")
        if not isinstance(batch_id, str) or len(batch_id) != 32:
            raise ValueError("invalid smart triage batch ID")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT * FROM smart_triage_batches WHERE audit_id=? AND report_sha256=? AND authorization_sha256=?",
                (record["audit_id"], record["report_sha256"], record["authorization_sha256"]),
            ).fetchone()
            if existing:
                return self.triage_batch_row(existing)
            db.execute(
                "INSERT INTO smart_triage_batches(id,audit_id,report_sha256,authorization_sha256,batch_consent_sha256,status,candidate_count,selected_count,candidate_manifest,operation_ids,created_at,error,r2_status,r2_candidate_manifest) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (batch_id, record["audit_id"], record["report_sha256"],
                 record["authorization_sha256"], record["batch_consent_sha256"],
                 record["status"], record["candidate_count"], record["selected_count"],
                 json.dumps(record["candidate_manifest"], sort_keys=True),
                 json.dumps(record.get("operation_ids", []), sort_keys=True),
                 record.get("created_at", now()), record.get("error"),
                 record.get("r2_status", "not_requested"),
                 json.dumps(record.get("r2_candidate_manifest", []), sort_keys=True)),
            )
            row = db.execute("SELECT * FROM smart_triage_batches WHERE id=?", (batch_id,)).fetchone()
        return self.triage_batch_row(row)

    def create_authorized_triage_batch(self, record, specs):
        if (not specs or len(specs) > MAX_TRIAGE_CANDIDATES_PER_ENDPOINT):
            raise ValueError("authorized triage batch must contain one to 10,000 candidates per endpoint")
        if any(spec.get("triage_authorization_sha256") != record["authorization_sha256"]
               or spec.get("smart_triage_batch_id") != record["id"] for spec in specs):
            raise ValueError("triage operation does not match its audit authorization batch")
        keys = [uuid.uuid4().hex for _ in specs]
        stamp = record.get("created_at", now())
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute(
                "SELECT * FROM smart_triage_batches WHERE audit_id=? AND report_sha256=? AND authorization_sha256=?",
                (record["audit_id"], record["report_sha256"], record["authorization_sha256"]),
            ).fetchone()
            if prior:
                batch = self.triage_batch_row(prior)
                return batch, [self.row(db.execute("SELECT * FROM operations WHERE id=?", (key,)).fetchone())
                               for key in batch["operation_ids"]]
            cancellation = db.execute(
                "SELECT report_sha256 FROM triage_cancellations WHERE audit_id=?",
                (record["audit_id"],),
            ).fetchone()
            if cancellation and (cancellation[0] is None
                                 or cancellation[0] == record["report_sha256"]):
                return None, []
            active = db.execute("SELECT count(*) FROM operations WHERE status IN ('queued','running') AND kind!='candidate_review_batch'").fetchone()[0]
            if active + len(specs) > MAX_AUTHORIZED_TRIAGE_QUEUE_ITEMS:
                raise ValueError(
                    "authorized triage queue capacity exceeded: active=" + str(active)
                    + ", requested=" + str(len(specs))
                    + ", limit=" + str(MAX_AUTHORIZED_TRIAGE_QUEUE_ITEMS)
                )
            db.execute(
                "INSERT INTO smart_triage_batches(id,audit_id,report_sha256,authorization_sha256,batch_consent_sha256,status,candidate_count,selected_count,candidate_manifest,operation_ids,created_at,error,r2_status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (record["id"], record["audit_id"], record["report_sha256"],
                 record["authorization_sha256"], record["batch_consent_sha256"], "queued",
                 record["candidate_count"], record["selected_count"],
                 json.dumps(record["candidate_manifest"], sort_keys=True),
                 json.dumps(keys), stamp, None,
                 record.get("r2_status", "not_requested")),
            )
            for key, spec in zip(keys, specs):
                db.execute("INSERT INTO operations(id,kind,spec,status,created_at) VALUES(?,?,?,?,?)",
                           (key, "agent_investigation", json.dumps(spec, sort_keys=True), "queued", stamp))
                db.execute("INSERT INTO operation_events(operation_id,created_at,stage,message) VALUES(?,?,?,?)",
                           (key, stamp, "queued", "Task-level consent authorized automatic Agent triage; no local cumulative usage cap"))
        with self.store.connect() as db:
            batch = self.triage_batch_row(db.execute(
                "SELECT * FROM smart_triage_batches WHERE id=?", (record["id"],)).fetchone())
            operations = [self.row(db.execute("SELECT * FROM operations WHERE id=?", (key,)).fetchone())
                          for key in keys]
        return batch, operations

    def triage_cancellation(self, audit_id, report_sha256=None):
        with self.store.connect() as db:
            row = db.execute(
                "SELECT * FROM triage_cancellations WHERE audit_id=?", (audit_id,)
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        if report_sha256 is not None and item["report_sha256"] not in {None, report_sha256}:
            return None
        return item

    def cancel_triage_for_job(self, audit_id, report_sha256=None, force=False):
        """Persist a triage stop and cancel only Agent work bound to this scan."""
        stamp = now()
        cancelled_ids = []
        stopped_running_ids = []
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            job_row = db.execute("SELECT status FROM jobs WHERE id=?", (audit_id,)).fetchone()
            if job_row is None:
                raise KeyError("job not found")
            batch_query = "SELECT id FROM smart_triage_batches WHERE audit_id=?"
            batch_args = [audit_id]
            operation_rows = db.execute(
                "SELECT id,status,spec FROM operations WHERE kind='agent_investigation'"
            ).fetchall()
            matching_operations = []
            for row in operation_rows:
                spec = json.loads(row["spec"])
                if spec.get("job_id") != audit_id:
                    continue
                if report_sha256 is not None and spec.get("report_sha256") != report_sha256:
                    continue
                if row["status"] in {"queued", "running"}:
                    matching_operations.append(row)
            if report_sha256 is not None:
                batch_query += " AND report_sha256=?"
                batch_args.append(report_sha256)
            batches = db.execute(batch_query, batch_args).fetchall()
            pending_r2 = any(
                db.execute(
                    "SELECT 1 FROM smart_triage_batches WHERE id=? AND r2_status='awaiting_r1'",
                    (row["id"],),
                ).fetchone()
                for row in batches
            )
            authorization = db.execute(
                "SELECT revoked_at FROM triage_authorizations WHERE audit_id=?", (audit_id,)
            ).fetchone()
            awaiting_scan_authorized_triage = bool(
                authorization and authorization["revoked_at"] is None
                and job_row["status"] not in {"completed", "completed_with_limitations",
                    "failed", "cancelled", "interrupted", "timed_out"}
            )
            if not force and not matching_operations and not pending_r2 and not awaiting_scan_authorized_triage:
                return {
                    "audit_id": audit_id, "report_sha256": report_sha256,
                    "cancelled_operation_count": 0, "stop_requested_operation_count": 0,
                    "stopped": False,
                }
            db.execute(
                "INSERT INTO triage_cancellations(audit_id,report_sha256,created_at) VALUES(?,?,?) "
                "ON CONFLICT(audit_id) DO UPDATE SET report_sha256=COALESCE(triage_cancellations.report_sha256,excluded.report_sha256)",
                (audit_id, report_sha256, stamp),
            )
            for batch_row in batches:
                db.execute(
                    "UPDATE smart_triage_batches SET status='cancelled', "
                    "r2_status=CASE WHEN r2_status IN ('awaiting_r1','queued','budget_limited','candidate_limit_reached') "
                    "THEN 'cancelled' ELSE r2_status END, "
                    "r2_error=CASE WHEN r2_status IN ('awaiting_r1','queued','budget_limited','candidate_limit_reached') "
                    "THEN 'triage cancelled by user' ELSE r2_error END WHERE id=?",
                    (batch_row["id"],),
                )
            for row in matching_operations:
                db.execute("UPDATE operations SET cancel_requested=1 WHERE id=?", (row["id"],))
                if row["status"] == "queued":
                    db.execute(
                        "UPDATE operations SET status='cancelled',finished_at=? WHERE id=?",
                        (stamp, row["id"]),
                    )
                    cancelled_ids.append(row["id"])
                else:
                    stopped_running_ids.append(row["id"])
        for operation_id in cancelled_ids:
            self.event(operation_id, "cancelled", "Queued Agent triage cancelled for this audit")
        for operation_id in stopped_running_ids:
            self.event(operation_id, "cancel_requested", "Agent triage stop requested for this audit")
        return {
            "audit_id": audit_id,
            "report_sha256": report_sha256,
            "cancelled_operation_count": len(cancelled_ids),
            "stop_requested_operation_count": len(stopped_running_ids),
            "stopped": True,
        }

    def triage_batch(self, batch_id):
        with self.store.connect() as db:
            row = db.execute("SELECT * FROM smart_triage_batches WHERE id=?", (batch_id,)).fetchone()
        return self.triage_batch_row(row)

    def triage_batches_pending_r2(self):
        with self.store.connect() as db:
            rows = db.execute(
                "SELECT * FROM smart_triage_batches WHERE r2_status='awaiting_r1' ORDER BY created_at,id"
            ).fetchall()
        return [self.triage_batch_row(row) for row in rows]

    def create_authorized_r2_batch(self, batch_id, decision_sha256, candidate_manifest,
                                   specs, status, error=None):
        allowed = {"queued", "not_needed", "budget_limited", "candidate_limit_reached",
                   "blocked_authorization_changed", "failed_selection"}
        if status == "budget_limited":
            status = "candidate_limit_reached"
        if status not in allowed or (specs and status not in {"queued", "candidate_limit_reached"}):
            raise ValueError("invalid conditional R2 batch decision")
        if len(specs) > MAX_TRIAGE_CANDIDATES_PER_ENDPOINT:
            raise ValueError("conditional R2 batch exceeds 10,000 candidates per endpoint")
        keys = [uuid.uuid4().hex for _ in specs]
        stamp = now()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM smart_triage_batches WHERE id=?", (batch_id,)).fetchone()
            if row is None:
                raise KeyError("triage batch not found")
            batch = self.triage_batch_row(row)
            if batch["r2_status"] != "awaiting_r1":
                existing = [self.row(db.execute("SELECT * FROM operations WHERE id=?", (key,)).fetchone())
                            for key in batch["r2_operation_ids"]]
                return batch, existing
            authorization = db.execute(
                "SELECT consent_sha256,revoked_at,snapshot FROM triage_authorizations WHERE audit_id=?",
                (batch["audit_id"],),
            ).fetchone()
            if (authorization is None or authorization["revoked_at"] is not None
                    or authorization["consent_sha256"] != batch["authorization_sha256"]):
                status, specs, keys = "blocked_authorization_changed", [], []
                error = "task-level source-egress authorization was revoked before R2 scheduling"
                db.execute(
                    "UPDATE smart_triage_batches SET r2_status=?,r2_operation_ids='[]',r2_candidate_manifest=?,r2_decision_sha256=?,r2_error=? WHERE id=? AND r2_status='awaiting_r1'",
                    (status, json.dumps(candidate_manifest, sort_keys=True), decision_sha256, error, batch_id),
                )
                saved = self.triage_batch_row(db.execute(
                    "SELECT * FROM smart_triage_batches WHERE id=?", (batch_id,)).fetchone())
                return saved, []
            r1_ids = set(batch["operation_ids"])
            r1_rows = {}
            if r1_ids:
                rows = db.execute(
                    "SELECT id,status,spec,result_sha256 FROM operations WHERE kind='agent_investigation'"
                ).fetchall()
                for item in rows:
                    spec = json.loads(item["spec"])
                    if item["id"] in r1_ids and spec.get("smart_triage_batch_id") == batch_id:
                        r1_rows[item["id"]] = item
                if (len(r1_rows) != len(r1_ids)
                        or any(item["status"] not in END for item in r1_rows.values())):
                    return batch, []
            snapshot = json.loads(authorization["snapshot"])
            uncapped_smart_r2 = all(
                spec.get("no_cumulative_token_ceiling") is True
                and spec.get("smart_triage_batch_id") == batch_id
                and spec.get("triage_authorization_sha256") == batch["authorization_sha256"]
                for spec in specs
            ) if specs else False
            if not uncapped_smart_r2 and len(specs) > int(snapshot.get("r2_candidate_limit", 0)):
                raise ValueError("conditional R2 candidate budget exceeded")
            selected_r1_candidates = {
                row.get("candidate_id") for row in batch["candidate_manifest"]
                if isinstance(row, dict) and row.get("state") == "selected"
            }
            r2_candidates = [spec.get("candidate_id") for spec in specs]
            if len(r2_candidates) != len(set(r2_candidates)):
                raise ValueError("conditional R2 batch repeats a candidate")
            for spec in specs:
                parent = r1_rows.get(spec.get("r1_operation_id"))
                parent_spec = json.loads(parent["spec"]) if parent else {}
                if (spec.get("triage_authorization_sha256") != batch["authorization_sha256"]
                        or spec.get("smart_triage_batch_id") != batch_id
                        or spec.get("mode") != "tool_agent"
                        or spec.get("report_sha256") != batch["report_sha256"]
                        or spec.get("candidate_id") not in selected_r1_candidates
                        or parent is None
                        or parent["status"] not in {"completed", "completed_with_limitations"}
                        or parent["result_sha256"] != spec.get("r1_result_sha256")
                        or parent_spec.get("mode") != "single_shot"
                        or parent_spec.get("candidate_id") != spec.get("candidate_id")
                        or parent_spec.get("report_sha256") != batch["report_sha256"]
                        or parent_spec.get("candidate_source_sha256") != spec.get("candidate_source_sha256")):
                    raise ValueError("conditional R2 operation is outside its completed fixed R1 result")
            if specs:
                active = db.execute("SELECT count(*) FROM operations WHERE status IN ('queued','running') AND kind!='candidate_review_batch'").fetchone()[0]
                if active + len(specs) > MAX_AUTHORIZED_TRIAGE_QUEUE_ITEMS:
                    raise ValueError(
                        "authorized triage queue capacity exceeded: active=" + str(active)
                        + ", requested=" + str(len(specs))
                        + ", limit=" + str(MAX_AUTHORIZED_TRIAGE_QUEUE_ITEMS)
                    )
                for key, spec in zip(keys, specs):
                    db.execute("INSERT INTO operations(id,kind,spec,status,created_at) VALUES(?,?,?,?,?)",
                               (key, "agent_investigation", json.dumps(spec, sort_keys=True), "queued", stamp))
                    db.execute("INSERT INTO operation_events(operation_id,created_at,stage,message) VALUES(?,?,?,?)",
                               (key, stamp, "queued", "R1 left critical source obligations unresolved; bounded conditional R2 was authorized"))
            db.execute(
                "UPDATE smart_triage_batches SET r2_status=?,r2_operation_ids=?,r2_candidate_manifest=?,r2_decision_sha256=?,r2_error=? WHERE id=? AND r2_status='awaiting_r1'",
                (status, json.dumps(keys), json.dumps(candidate_manifest, sort_keys=True),
                 decision_sha256, error, batch_id),
            )
            saved = self.triage_batch_row(db.execute(
                "SELECT * FROM smart_triage_batches WHERE id=?", (batch_id,)).fetchone())
            operations = [self.row(db.execute("SELECT * FROM operations WHERE id=?", (key,)).fetchone())
                          for key in keys]
        return saved, operations

    def triage_batches_for_job(self, audit_id, report_sha256=None):
        with self.store.connect() as db:
            query = "SELECT * FROM smart_triage_batches WHERE audit_id=?"
            args = [audit_id]
            if report_sha256 is not None:
                query += " AND report_sha256=?"
                args.append(report_sha256)
            query += " ORDER BY created_at"
            return [self.triage_batch_row(row) for row in db.execute(query, args)]

    def create_audit_snapshots(self, risk_payload, report_payload, markdown_builder):
        """Persist content-addressed risk and combined-report snapshots atomically."""
        audit_id = report_payload.get("audit_id")
        report_sha256 = report_payload.get("source_report_sha256")
        policy_version = risk_payload.get("policy_version")
        if (not isinstance(audit_id, str) or len(audit_id) != 32
                or not isinstance(report_sha256, str) or len(report_sha256) != 64
                or not isinstance(policy_version, str) or not policy_version):
            raise ValueError("invalid audit snapshot binding")

        def canonical(value):
            return json.dumps(value, sort_keys=True, ensure_ascii=False,
                              separators=(",", ":"))

        risk_content = canonical(risk_payload)
        risk_digest = hashlib.sha256(risk_content.encode("utf-8")).hexdigest()
        risk_id = hashlib.sha256(
            (audit_id + report_sha256 + risk_digest).encode("utf-8")
        ).hexdigest()[:32]
        report_document = {**report_payload, "risk_snapshot_id": risk_id,
                           "risk_snapshot_sha256": risk_digest}
        report_digest = hashlib.sha256(canonical(report_document).encode("utf-8")).hexdigest()
        snapshot_id = hashlib.sha256(
            (audit_id + report_sha256 + report_digest).encode("utf-8")
        ).hexdigest()[:32]

        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            prior_risk = db.execute(
                "SELECT * FROM risk_snapshots WHERE audit_id=? AND report_sha256=? AND content_sha256=?",
                (audit_id, report_sha256, risk_digest),
            ).fetchone()
            if prior_risk:
                risk_id = prior_risk["id"]
                report_document["risk_snapshot_id"] = risk_id
            else:
                db.execute(
                    "INSERT INTO risk_snapshots(id,audit_id,report_sha256,content_sha256,policy_version,content,created_at) VALUES(?,?,?,?,?,?,?)",
                    (risk_id, audit_id, report_sha256, risk_digest, policy_version,
                     risk_content, now()),
                )
            prior_report = db.execute(
                "SELECT * FROM report_snapshots WHERE audit_id=? AND report_sha256=? AND content_sha256=?",
                (audit_id, report_sha256, report_digest),
            ).fetchone()
            if prior_report:
                row = dict(prior_report)
                risk_row = db.execute("SELECT * FROM risk_snapshots WHERE id=?", (row["risk_snapshot_id"],)).fetchone()
                return self._audit_snapshot_result(row, risk_row)

            created_at = now()
            document = {
                **report_document,
                "report_snapshot_id": snapshot_id,
                "report_snapshot_sha256": report_digest,
                "created_at": created_at,
            }
            json_content = json.dumps(document, sort_keys=True, ensure_ascii=False, indent=2) + "\n"
            markdown_content = markdown_builder(document)
            json_digest = hashlib.sha256(json_content.encode("utf-8")).hexdigest()
            markdown_digest = hashlib.sha256(markdown_content.encode("utf-8")).hexdigest()
            db.execute(
                "INSERT INTO report_snapshots(id,audit_id,report_sha256,risk_snapshot_id,content_sha256,json_sha256,markdown_sha256,json_content,markdown_content,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (snapshot_id, audit_id, report_sha256, risk_id, report_digest,
                 json_digest, markdown_digest, json_content, markdown_content, created_at),
            )
            row = dict(db.execute("SELECT * FROM report_snapshots WHERE id=?", (snapshot_id,)).fetchone())
            risk_row = db.execute("SELECT * FROM risk_snapshots WHERE id=?", (risk_id,)).fetchone()
        return self._audit_snapshot_result(row, risk_row)

    @staticmethod
    def _audit_snapshot_result(report_row, risk_row):
        if risk_row is None:
            raise ValueError("report snapshot risk binding is missing")
        risk_content = risk_row["content"]
        if hashlib.sha256(risk_content.encode("utf-8")).hexdigest() != risk_row["content_sha256"]:
            raise ValueError("risk snapshot integrity mismatch")
        for field, digest_field in (("json_content", "json_sha256"),
                                    ("markdown_content", "markdown_sha256")):
            if hashlib.sha256(report_row[field].encode("utf-8")).hexdigest() != report_row[digest_field]:
                raise ValueError("report snapshot integrity mismatch")
        return {
            "id": report_row["id"], "audit_id": report_row["audit_id"],
            "report_sha256": report_row["report_sha256"],
            "risk_snapshot_id": report_row["risk_snapshot_id"],
            "content_sha256": report_row["content_sha256"],
            "json_sha256": report_row["json_sha256"],
            "markdown_sha256": report_row["markdown_sha256"],
            "created_at": report_row["created_at"],
            "json_content": report_row["json_content"],
            "markdown_content": report_row["markdown_content"],
        }

    def audit_report_snapshots(self, audit_id):
        with self.store.connect() as db:
            rows = db.execute(
                "SELECT id,audit_id,report_sha256,risk_snapshot_id,content_sha256,json_sha256,markdown_sha256,created_at FROM report_snapshots WHERE audit_id=? ORDER BY created_at,id",
                (audit_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def audit_report_snapshot(self, audit_id, snapshot_id):
        if (len(audit_id) != 32 or len(snapshot_id) != 32
                or any(char not in "0123456789abcdef" for char in audit_id + snapshot_id)):
            raise KeyError("report snapshot not found")
        with self.store.connect() as db:
            row = db.execute(
                "SELECT * FROM report_snapshots WHERE audit_id=? AND id=?",
                (audit_id, snapshot_id),
            ).fetchone()
            if row is None:
                raise KeyError("report snapshot not found")
            risk = db.execute("SELECT * FROM risk_snapshots WHERE id=?", (row["risk_snapshot_id"],)).fetchone()
        return self._audit_snapshot_result(dict(row), risk)

    def smart_triage_operations(self, batch_id):
        with self.store.connect() as db:
            rows = [self.row(row) for row in db.execute(
                "SELECT * FROM operations WHERE kind='agent_investigation' ORDER BY created_at")]
        return [row for row in rows if row["spec"].get("smart_triage_batch_id") == batch_id]

    def create_with_scans(self, kind, spec, repository_id, scan_specs):
        """Create an operation and its immutable endpoint jobs in one DB transaction."""
        if kind not in {"revision_range", "version_matrix", "branch_comparison", "recent_window_comparison"} or not scan_specs:
            raise ValueError("invalid scan operation")
        key = uuid.uuid4().hex
        job_ids = [uuid.uuid4().hex for _ in scan_specs]
        # An HTTP retry with the same reviewed endpoint consents must not schedule
        # duplicate Provider calls; a fresh preview nonce is a deliberate new run.
        authorized = [item.get("triage_authorization", {}) for item in scan_specs]
        consent_key = None
        if all(a.get("authorized") is True for a in authorized):
            binding = {"kind": kind, "repository_id": repository_id,
                       "endpoints": [{"plan_sha256": item.get("plan_sha256"),
                                      "consent_sha256": auth["consent_sha256"]}
                                     for item, auth in zip(scan_specs, authorized)]}
            consent_key = hashlib.sha256(
                json.dumps(binding, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()
        spec = {**spec, "scan_ids": job_ids}
        if consent_key:
            spec["operation_consent_group_sha256"] = consent_key
        stamp = now()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if consent_key:
                for prior in db.execute("SELECT * FROM operations WHERE kind=?", (kind,)):
                    previous = json.loads(prior["spec"])
                    if previous.get("operation_consent_group_sha256") == consent_key:
                        return self.row(prior)
            if db.execute("SELECT 1 FROM repositories WHERE id=?", (repository_id,)).fetchone() is None:
                raise KeyError("repository not found")
            if db.execute("SELECT count(*) FROM operations WHERE status IN ('queued','running')").fetchone()[0] >= 100:
                raise ValueError("operation queue full")
            if db.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0] + len(job_ids) > 100:
                raise ValueError("scan queue capacity reached")
            db.execute("INSERT INTO operations(id,kind,spec,status,created_at) VALUES(?,?,?,?,?)",
                       (key, kind, json.dumps(spec, sort_keys=True), "queued", stamp))
            for job_id, scan_spec in zip(job_ids, scan_specs):
                db.execute("INSERT INTO jobs(id,repository_id,spec,status,stage,created_at) VALUES(?,?,?,?,?,?)",
                           (job_id, repository_id, json.dumps(scan_spec, sort_keys=True), "queued", "source_pinned", stamp))
                db.execute("INSERT INTO events(job_id,created_at,stage,message) VALUES(?,?,?,?)",
                           (job_id, stamp, "source_pinned", "Requested revision resolved to immutable commit/tree"))
                authorization = scan_spec.get("triage_authorization")
                if isinstance(authorization, dict) and authorization.get("authorized") is True:
                    digest, snapshot = authorization.get("consent_sha256"), authorization.get("snapshot")
                    if (not isinstance(digest, str) or len(digest) != 64
                            or not isinstance(snapshot, dict)):
                        raise ValueError("invalid task-level triage authorization snapshot")
                    binding = snapshot.get("binding", {})
                    if (binding.get("plan_sha256") != scan_spec.get("plan_sha256")
                            or binding.get("workflow_sha256") != scan_spec.get("workflow_sha256")):
                        raise ValueError("endpoint model authorization is bound to another scan plan or workflow")
                    db.execute("INSERT INTO triage_authorizations(audit_id,consent_sha256,snapshot,created_at) VALUES(?,?,?,?)",
                               (job_id, digest, json.dumps(snapshot, sort_keys=True), stamp))
            db.execute("INSERT INTO operation_events(operation_id,created_at,stage,message) VALUES(?,?,?,?)",
                       (key, stamp, "queued", "Operation and endpoint scans committed atomically"))
        return self.get(key)

    @staticmethod
    def row(row):
        if row is None:
            raise KeyError("operation not found")
        item = dict(row)
        item["spec"] = json.loads(item["spec"])
        return item

    def get(self, key):
        with self.store.connect() as db:
            return self.row(db.execute("SELECT * FROM operations WHERE id=?", (key,)).fetchone())

    def list(self):
        with self.store.connect() as db:
            return [self.row(r) for r in db.execute("SELECT * FROM operations ORDER BY created_at DESC LIMIT 200")]

    def audit_parent_for_scan(self, job_id):
        """Resolve a multi-endpoint audit parent without guessing across parents."""
        if not isinstance(job_id, str) or not job_id:
            raise ValueError("invalid scan job ID")
        kinds = {"revision_range", "version_matrix", "branch_comparison", "recent_window_comparison"}
        with self.store.connect() as db:
            rows = list(db.execute("SELECT * FROM operations WHERE kind IN (?,?,?,?)",
                                   tuple(sorted(kinds))))
        parents = []
        for raw in rows:
            row = self.row(raw)
            if job_id in row["spec"].get("scan_ids", []):
                parents.append(row)
        if len(parents) > 1:
            raise ValueError("scan job is linked to multiple audit operations; shared budget cannot be resolved")
        return parents[0] if parents else None

    def report_operations_for_case(self, case_id, limit=20):
        """Return result-bearing operations bound to one case, with explicit truncation."""
        if not isinstance(case_id, str) or not case_id.strip():
            raise ValueError("case ID must be a non-empty string")
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 200:
            raise ValueError("case report operation limit must be between 1 and 200")
        predicate = "json_extract(spec, '$.case_id')=? AND result_sha256 IS NOT NULL"
        with self.store.connect() as db:
            total = db.execute(
                "SELECT count(*) FROM operations WHERE " + predicate, (case_id,)
            ).fetchone()[0]
            rows = list(db.execute(
                "SELECT * FROM operations WHERE " + predicate
                + " ORDER BY created_at DESC, id DESC LIMIT ?",
                (case_id, limit),
            ))
        items = [self.row(row) for row in rows]
        return {"items": items, "total": total, "included": len(items),
                "truncated": total > len(items), "limit": limit}

    def agent_investigations_for_job(self, job_id, report_sha256=None):
        with self.store.connect() as db:
            rows = list(db.execute(
                "SELECT id,status,spec,created_at,finished_at,result_sha256,cancel_requested FROM operations "
                "WHERE kind='agent_investigation' ORDER BY created_at"))
        items = []
        for row in rows:
            spec = json.loads(row["spec"])
            if spec.get("job_id") != job_id:
                continue
            if report_sha256 and spec.get("report_sha256") != report_sha256:
                continue
            items.append({
                "id": row["id"],
                "status": row["status"],
                "candidate_id": spec.get("candidate_id"),
                "mode": spec.get("mode"),
                "created_at": row["created_at"],
                "finished_at": row["finished_at"],
                "result_sha256": row["result_sha256"],
                "cancel_requested": bool(row["cancel_requested"]),
            })
        return items

    def candidate_review_queue(self):
        with self.store.connect() as db:
            rows = list(db.execute("SELECT id,status,spec,created_at FROM operations WHERE kind='candidate_review_batch' ORDER BY created_at"))
        counts = {"queued_batches": 0, "running_batches": 0, "finished_batches": 0,
                  "queued_candidates": 0, "running_candidates": 0}
        for row in rows:
            spec = json.loads(row["spec"])
            candidates = int(spec.get("candidate_count_at_enqueue", 0))
            if row["status"] == "queued":
                counts["queued_batches"] += 1
                counts["queued_candidates"] += candidates
            elif row["status"] == "running":
                counts["running_batches"] += 1
                counts["running_candidates"] += candidates
            else:
                counts["finished_batches"] += 1
        from .agent import public_status
        return {"schema_version": 1, **counts,
                "model_provider_configured": public_status(self.store.root)["configured"],
                "automatic_batch_processing_enabled": False,
                "task_authorized_auto_triage_enabled": True,
                "limitations": ["The legacy candidate_review_batch pointer is not executed; only a separate task-level consent can queue bounded R1 work.",
                                "Zero-candidate and partial/unanalyzed source coverage remain in scan reports and are not second-pass Agent reviews."]}

    def retry_interrupted_smart_operation(self, key):
        """Queue an explicit retry while preserving the interrupted attempt and its consent binding."""
        new_key = uuid.uuid4().hex
        stamp = now()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute("SELECT * FROM operations WHERE id=?", (key,)).fetchone()
            if old is None:
                raise KeyError("operation not found")
            spec = json.loads(old["spec"])
            if (old["kind"] != "agent_investigation" or old["status"] != "interrupted"
                    or old["result_sha256"] or old["cancel_requested"]):
                raise ValueError("only an interrupted, result-free authorized smart investigation can be retried")
            batch_id = spec.get("smart_triage_batch_id")
            audit_id = spec.get("job_id")
            report_sha256 = spec.get("report_sha256")
            authorization_sha256 = spec.get("triage_authorization_sha256")
            if not all(isinstance(value, str) and value for value in
                       (batch_id, audit_id, report_sha256, authorization_sha256)):
                raise ValueError("interrupted operation is not bound to a task-level smart audit")
            authorization = db.execute(
                "SELECT consent_sha256,revoked_at FROM triage_authorizations WHERE audit_id=?",
                (audit_id,),
            ).fetchone()
            if (authorization is None or authorization["revoked_at"] is not None
                    or authorization["consent_sha256"] != authorization_sha256):
                raise ValueError("task-level source-egress authorization is missing, changed, or revoked")
            batch_row = db.execute(
                "SELECT * FROM smart_triage_batches WHERE id=? AND audit_id=? AND report_sha256=? AND authorization_sha256=?",
                (batch_id, audit_id, report_sha256, authorization_sha256),
            ).fetchone()
            if batch_row is None:
                raise ValueError("original smart batch, report, or authorization binding is unavailable")
            batch = self.triage_batch_row(batch_row)
            current_job = db.execute("SELECT report_sha256 FROM jobs WHERE id=?", (audit_id,)).fetchone()
            if current_job is None or current_job["report_sha256"] != report_sha256:
                raise ValueError("the original fixed report is no longer the current audit report")
            member_ids = set(batch["operation_ids"] + batch["r2_operation_ids"])
            if key not in member_ids:
                raise ValueError("operation is not part of the original smart audit batch")
            candidate_id = spec.get("candidate_id")
            if spec.get("mode") == "single_shot":
                eligible_manifest = batch["candidate_manifest"]
            elif spec.get("mode") == "tool_agent":
                eligible_manifest = batch["r2_candidate_manifest"]
            else:
                eligible_manifest = []
            if not any(isinstance(row, dict) and row.get("candidate_id") == candidate_id
                       and row.get("state") == "selected" for row in eligible_manifest):
                raise ValueError("candidate is not selected in the original authorized audit batch")
            cancellation = db.execute(
                "SELECT report_sha256 FROM triage_cancellations WHERE audit_id=?",
                (audit_id,),
            ).fetchone()
            if cancellation and cancellation[0] in {None, report_sha256}:
                raise ValueError("the original audit's smart investigation was cancelled")
            candidate_id = spec.get("candidate_id")
            if not isinstance(candidate_id, str) or not candidate_id:
                raise ValueError("interrupted operation lacks a fixed candidate identity")
            siblings = []
            for row in db.execute(
                    "SELECT id,status,spec FROM operations WHERE kind='agent_investigation'"):
                sibling_spec = json.loads(row["spec"])
                if (sibling_spec.get("smart_triage_batch_id") == batch_id
                        and sibling_spec.get("candidate_id") == candidate_id):
                    siblings.append((row, sibling_spec))
            if any(row["status"] in {"queued", "running"} for row, _ in siblings):
                raise ValueError("another attempt for this fixed candidate is already active")
            root_key = spec.get("retry_root_operation_id") or key
            retry_attempt = 1 + max(
                (int(sibling_spec.get("retry_attempt", 0))
                 for _, sibling_spec in siblings
                 if isinstance(sibling_spec.get("retry_attempt", 0), int)
                 and not isinstance(sibling_spec.get("retry_attempt", 0), bool)),
                default=0,
            )
            retry_spec = dict(spec)
            retry_spec.update({
                "retry_parent_operation_id": key,
                "retry_root_operation_id": root_key,
                "retry_attempt": retry_attempt,
            })
            db.execute(
                "INSERT INTO operations(id,kind,spec,status,created_at) VALUES(?,?,?,?,?)",
                (new_key, "agent_investigation", json.dumps(retry_spec, sort_keys=True), "queued", stamp),
            )
            if spec.get("mode") == "single_shot":
                operation_ids = list(batch["operation_ids"])
                operation_ids.append(new_key)
                db.execute("UPDATE smart_triage_batches SET operation_ids=? WHERE id=?",
                           (json.dumps(operation_ids), batch_id))
            else:
                operation_ids = list(batch["r2_operation_ids"])
                operation_ids.append(new_key)
                db.execute("UPDATE smart_triage_batches SET r2_operation_ids=? WHERE id=?",
                           (json.dumps(operation_ids), batch_id))
            message = ("Explicit retry queued as " + new_key
                       + "; same candidate, commit, report and source-egress consent; "
                       + "the Provider may be called again and may bill this attempt.")
            db.execute(
                "INSERT INTO operation_events(operation_id,created_at,stage,message) VALUES(?,?,?,?)",
                (key, stamp, "retry_created", message),
            )
            db.execute(
                "INSERT INTO operation_events(operation_id,created_at,stage,message) VALUES(?,?,?,?)",
                (new_key, stamp, "queued",
                 "Explicit retry of " + key + "; source, report and original consent bindings are unchanged."),
            )
        return self.get(new_key)
    def event(self, key, stage, message):
        with self.store.connect() as db:
            db.execute("INSERT INTO operation_events(operation_id,created_at,stage,message) VALUES(?,?,?,?)",
                       (key, now(), stage, message[:4000]))

    def events(self, key):
        self.get(key)
        with self.store.connect() as db:
            return [dict(r) for r in db.execute("SELECT * FROM operation_events WHERE operation_id=? ORDER BY id", (key,))]

    def claim(self, validation=False):
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            sign = "=" if validation else "!="
            row = db.execute("SELECT id FROM operations WHERE status='queued' AND kind " + sign + " 'validation' AND kind!='candidate_review_batch' ORDER BY created_at LIMIT 1").fetchone()
            if not row:
                return None
            db.execute("UPDATE operations SET status='running',started_at=? WHERE id=?", (now(), row[0]))
            return self.row(db.execute("SELECT * FROM operations WHERE id=?", (row[0],)).fetchone())

    def cancel(self, key):
        cancelled_ids = []
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.row(db.execute("SELECT * FROM operations WHERE id=?", (key,)).fetchone())
            if row["kind"] == "candidate_review_batch" and row["status"] not in END:
                raise ValueError("candidate review batches cannot be cancelled; all candidates must remain queued until review or explicit resolution")
            targets = [row]
            if row["kind"] in {"revision_range", "version_matrix", "branch_comparison", "recent_window_comparison"}:
                for item in db.execute(
                        "SELECT * FROM operations WHERE kind IN ('progressive_quick_screen','agent_investigation')"):
                    child_spec = json.loads(item["spec"])
                    child_audit = (child_spec.get("audit_operation_id")
                                   if item["kind"] == "progressive_quick_screen"
                                   else child_spec.get("progressive_audit_operation_id"))
                    if child_audit == key:
                        targets.append(self.row(item))
            pair_id = row["spec"].get("pair_id")
            if pair_id and row["kind"] == "agent_investigation" and row["status"] not in END:
                targets = [self.row(item) for item in db.execute(
                    "SELECT * FROM operations WHERE kind='agent_investigation'")
                    if json.loads(item["spec"]).get("pair_id") == pair_id]
            stamp = now()
            for target in targets:
                if target["status"] in END:
                    continue
                if target["kind"] == "source_sync_batch" and target["status"] == "running":
                    # Keep the parent Worker alive so the handler can stop its active
                    # Git process and persist completed per-repository results.
                    db.execute(
                        "INSERT OR IGNORE INTO operation_cancellations(operation_id,requested_at,reason) VALUES(?,?,?)",
                        (target["id"], stamp, "user_requested"),
                    )
                else:
                    db.execute("UPDATE operations SET cancel_requested=1 WHERE id=?", (target["id"],))
                    if target["status"] == "queued":
                        db.execute("UPDATE operations SET status='cancelled',finished_at=? WHERE id=?",
                                   (stamp, target["id"]))
                cancelled_ids.append(target["id"])
        # Cancel owned endpoint scans, never unrelated jobs.
        for job in row["spec"].get("scan_ids", []):
            self.store.cancel(job)
        for target_id in cancelled_ids:
            target_kind = self.get(target_id)["kind"]
            message = ("Source sync cancellation requested; active Git transfer will stop safely"
                       if target_kind in {"source_sync", "source_sync_batch"} else
                       "Cancellation propagated to the paired R1/R2 experiment" if pair_id else
                       "Cancellation requested")
            self.event(target_id, "cancel_requested", message)
        return self.get(key)

    def batch_sync_cancel_requested(self, key):
        with self.store.connect() as db:
            row = db.execute(
                "SELECT 1 FROM operation_cancellations WHERE operation_id=?", (key,)
            ).fetchone()
        return row is not None

    def source_sync_cancel_requested(self, key):
        """Read cancellation state for a running single or batch source sync."""
        with self.store.connect() as db:
            row = db.execute(
                "SELECT o.cancel_requested, EXISTS("
                "SELECT 1 FROM operation_cancellations c WHERE c.operation_id=o.id) "
                "FROM operations o WHERE o.id=?", (key,)
            ).fetchone()
        return bool(row and (row[0] or row[1]))

    def finish(self, key, result=None, error=None, state=None):
        digest = None
        if result is not None:
            folder = self.directory(key)
            folder.mkdir(parents=True, exist_ok=True)
            data = (json.dumps(result, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()
            path = folder / "result.json"
            temporary = folder / "result.pending"
            temporary.write_bytes(data)
            temporary.replace(path)
            digest = hashlib.sha256(data).hexdigest()
        status = state or (result or {}).get("status", "failed")
        if status not in END:
            raise ValueError("invalid operation final status")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = self.row(db.execute("SELECT * FROM operations WHERE id=?", (key,)).fetchone())
            if current["status"] != "running":
                return
            if current["cancel_requested"]:
                status, digest = "cancelled", None
            elif (current["kind"] == "source_sync_batch"
                  and db.execute("SELECT 1 FROM operation_cancellations WHERE operation_id=?", (key,)).fetchone()):
                status = "cancelled"
                if result is not None:
                    result["status"] = "cancelled"
                    result["cancellation_requested"] = True
                    folder = self.directory(key)
                    folder.mkdir(parents=True, exist_ok=True)
                    data = (json.dumps(result, sort_keys=True, ensure_ascii=False, indent=2) + "\n").encode()
                    path = folder / "result.json"
                    temporary = folder / "result.pending"
                    temporary.write_bytes(data)
                    temporary.replace(path)
                    digest = hashlib.sha256(data).hexdigest()
            db.execute("UPDATE operations SET status=?,result_sha256=?,error=?,finished_at=? WHERE id=?",
                       (status, digest, error, now(), key))
        self.event(key, status, error or "Operation result committed")

    def result(self, key):
        task = self.get(key)
        if not task["result_sha256"]:
            raise ValueError("no committed result; analysis remains unknown")
        data = (self.directory(key) / "result.json").read_bytes()
        if hashlib.sha256(data).hexdigest() != task["result_sha256"]:
            raise ValueError("operation result integrity mismatch")
        return json.loads(data)

    def recover(self, validation=False):
        with self.store.connect() as db:
            sign = "=" if validation else "!="
            db.execute("UPDATE operations SET status='interrupted',finished_at=?,error=? WHERE status='running' AND kind " + sign + " 'validation'",
                       (now(), "Worker stopped; retry explicitly"))

    def record_agent_baseline_review(self, record):
        body = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        stamp = now()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute("SELECT 1 FROM agent_baseline_reviews WHERE experiment_id=? AND job_id=? AND candidate_id=? LIMIT 1",
                                  (record["experiment_id"], record["job_id"], record["candidate_id"])).fetchone()
            if existing:
                raise ValueError("R0 baseline already exists for this experiment candidate")
            db.execute(
                "INSERT INTO agent_baseline_reviews(experiment_id,repository,source_commit,job_id,candidate_id,record,record_sha256,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (record["experiment_id"], record["repository"], record["commit"], record["job_id"],
                 record["candidate_id"], body, digest, stamp))
            review_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]
        return {"id": review_id, **record, "record_sha256": digest, "created_at": stamp}

    def agent_baseline_reviews(self, experiment_id=None):
        query = "SELECT * FROM agent_baseline_reviews"
        params = ()
        if experiment_id:
            query += " WHERE experiment_id=?"
            params = (experiment_id,)
        query += " ORDER BY id"
        with self.store.connect() as db:
            rows = db.execute(query, params).fetchall()
        output = []
        for row in rows:
            body = row["record"]
            if hashlib.sha256(body.encode("utf-8")).hexdigest() != row["record_sha256"]:
                raise ValueError("agent baseline review integrity mismatch")
            output.append({"id": row["id"], **json.loads(body),
                           "record_sha256": row["record_sha256"], "created_at": row["created_at"]})
        return output

    def agent_evaluation_summary(self):
        groups = {}
        paired = {}
        execution_groups = {}
        baseline_reviews = self.agent_baseline_reviews()
        baseline_by_candidate = {}
        for baseline in baseline_reviews:
            key = (baseline["experiment_id"], baseline["repository"], baseline["commit"], baseline["candidate_id"])
            baseline_by_candidate.setdefault(key, []).append(baseline)
        for task in self.list():
            if task["kind"] != "agent_investigation":
                continue
            # This operational telemetry is separate from human feedback and
            # never measures vulnerability correctness.
            result = self.result(task["id"]) if task["result_sha256"] else {}
            provider = result.get("provider") if isinstance(result.get("provider"), dict) else {}
            spec = task.get("spec") if isinstance(task.get("spec"), dict) else {}
            exec_dimensions = {
                "mode": result.get("mode") or spec.get("mode") or "unknown",
                "provider": provider.get("provider") or spec.get("provider") or "unknown",
                "endpoint_host": provider.get("endpoint_host") or spec.get("provider_host") or "unknown",
                "model": provider.get("model") or spec.get("provider_model") or spec.get("model") or "unknown",
                "prompt_version": result.get("prompt_version") or spec.get("prompt_version") or "unknown",
                "tool_policy_version": result.get("tool_policy_version") or spec.get("tool_policy_version") or "unknown",
            }
            exec_key = tuple(exec_dimensions[name] or "" for name in
                             ("mode", "provider", "endpoint_host", "model", "prompt_version", "tool_policy_version"))
            execution = execution_groups.setdefault(exec_key, {
                **exec_dimensions, "operation_ids": set(), "status_counts": {},
                "result_count": 0, "schema_validation": {"accepted": 0, "rejected": 0, "unknown": 0},
                "repair_operation_count": 0, "repair_attempts": 0,
                "tool_calls": {"completed": 0, "rejected": 0, "unknown_status": 0},
                "tool_trace_operation_count": 0, "model_tool_calls_skipped": 0,
                "usage": {"complete": 0, "incomplete": 0, "unknown": 0},
                "token_usage": {"complete_operation_count": 0, "input_tokens": 0,
                                 "output_tokens": 0, "total_tokens": 0},
                "cost_estimate_status_counts": {}, "cost_estimate_aggregates": {},
                "wall_seconds": [], "child_execution_seconds": [], "process_peak_rss_bytes": [],
                "wall_unknown": 0, "child_wall_unknown": 0, "rss_unknown": 0,
            })
            execution["operation_ids"].add(task["id"])
            state = task["status"]
            try:
                started_at = datetime.fromisoformat(task["started_at"]) if task.get("started_at") else None
                finished_at = datetime.fromisoformat(task["finished_at"]) if task.get("finished_at") else None
                wall = (finished_at - started_at).total_seconds() if started_at and finished_at else None
                if wall is not None and wall >= 0:
                    execution["wall_seconds"].append(wall)
                else:
                    execution["wall_unknown"] += 1
            except (TypeError, ValueError):
                execution["wall_unknown"] += 1
            execution["status_counts"][state] = execution["status_counts"].get(state, 0) + 1
            if task["result_sha256"]:
                execution["result_count"] += 1
                validation = result.get("structured_answer_validation")
                if validation == "accepted":
                    execution["schema_validation"]["accepted"] += 1
                elif isinstance(validation, str) and validation.startswith("rejected"):
                    execution["schema_validation"]["rejected"] += 1
                else:
                    execution["schema_validation"]["unknown"] += 1
                repairs = result.get("validation_repair_attempts")
                if isinstance(repairs, int) and not isinstance(repairs, bool) and repairs >= 0:
                    execution["repair_attempts"] += repairs
                    execution["repair_operation_count"] += int(repairs > 0)
                trace = result.get("tool_calls")
                if isinstance(trace, list):
                    execution["tool_trace_operation_count"] += 1
                    for call in trace:
                        if not isinstance(call, dict):
                            execution["tool_calls"]["unknown_status"] += 1
                        elif call.get("status") in {"completed", "rejected"}:
                            execution["tool_calls"][call["status"]] += 1
                        else:
                            execution["tool_calls"]["unknown_status"] += 1
                skipped = result.get("model_tool_calls_skipped")
                if isinstance(skipped, int) and not isinstance(skipped, bool) and skipped >= 0:
                    execution["model_tool_calls_skipped"] += skipped
                usage = result.get("model_usage")
                if isinstance(usage, dict) and usage.get("usage_complete") is True:
                    input_tokens, output_tokens = usage.get("input_tokens"), usage.get("output_tokens")
                    if all(isinstance(value, int) and not isinstance(value, bool) and value >= 0
                           for value in (input_tokens, output_tokens)):
                        execution["usage"]["complete"] += 1
                        execution["token_usage"]["complete_operation_count"] += 1
                        execution["token_usage"]["input_tokens"] += input_tokens
                        execution["token_usage"]["output_tokens"] += output_tokens
                        execution["token_usage"]["total_tokens"] += input_tokens + output_tokens
                    else:
                        execution["usage"]["incomplete"] += 1
                elif isinstance(usage, dict) and usage.get("usage_complete") is False:
                    execution["usage"]["incomplete"] += 1
                else:
                    execution["usage"]["unknown"] += 1

                telemetry = result.get("execution_telemetry")
                telemetry = telemetry if isinstance(telemetry, dict) else {}
                child_wall = telemetry.get("wall_seconds")
                if (isinstance(child_wall, (int, float)) and not isinstance(child_wall, bool)
                        and child_wall >= 0):
                    execution["child_execution_seconds"].append(float(child_wall))
                else:
                    execution["child_wall_unknown"] += 1
                peak_rss = telemetry.get("process_peak_rss_bytes")
                if isinstance(peak_rss, int) and not isinstance(peak_rss, bool) and peak_rss > 0:
                    execution["process_peak_rss_bytes"].append(peak_rss)
                else:
                    execution["rss_unknown"] += 1

                estimate = usage.get("cost_estimate") if isinstance(usage, dict) else None
                estimate_status = estimate.get("status") if isinstance(estimate, dict) else None
                estimate_status = estimate_status or "unavailable"
                execution["cost_estimate_status_counts"][estimate_status] = (
                    execution["cost_estimate_status_counts"].get(estimate_status, 0) + 1)
                fields = ({"estimated_amount": ("amount_usd",),
                           "estimated_range": ("minimum_usd", "maximum_usd")}.get(estimate_status))
                if fields and isinstance(estimate, dict):
                    try:
                        amounts = {name: Decimal(str(estimate[name])) for name in fields}
                        if any(not value.is_finite() or value < 0 for value in amounts.values()):
                            raise InvalidOperation
                    except (KeyError, InvalidOperation, TypeError, ValueError):
                        execution["cost_estimate_status_counts"]["malformed_estimate"] = (
                            execution["cost_estimate_status_counts"].get("malformed_estimate", 0) + 1)
                    else:
                        rate_key = (estimate_status, estimate.get("rate_card_id") or "unknown",
                                    estimate.get("currency") or "unknown",
                                    estimate.get("alternative_currency") or "",
                                    estimate.get("rate_source_url") or "")
                        bucket = execution["cost_estimate_aggregates"].setdefault(rate_key, {
                            "status": estimate_status, "rate_card_id": rate_key[1],
                            "currency": rate_key[2], "alternative_currency": rate_key[3],
                            "rate_source_url": rate_key[4],
                            "operation_count": 0, "actual_charge_verified": False,
                            "amounts": {name: Decimal(0) for name in fields},
                            "amount_counts": {name: 0 for name in fields},
                        })
                        bucket["operation_count"] += 1
                        for name, value in amounts.items():
                            bucket["amounts"][name] += value
                            bucket["amount_counts"][name] += 1
                        cny_amount = estimate.get("amount_cny")
                        if estimate_status == "estimated_amount" and cny_amount is not None:
                            try:
                                cny_amount = Decimal(str(cny_amount))
                                if not cny_amount.is_finite() or cny_amount < 0:
                                    raise InvalidOperation
                            except (InvalidOperation, TypeError, ValueError):
                                cny_amount = None
                            if cny_amount is not None:
                                if "amount_cny" not in bucket["amounts"]:
                                    bucket["amounts"]["amount_cny"] = Decimal(0)
                                    bucket["amount_counts"]["amount_cny"] = 0
                                bucket["amounts"]["amount_cny"] += cny_amount
                                bucket["amount_counts"]["amount_cny"] += 1
            else:
                execution["schema_validation"]["unknown"] += 1
                execution["usage"]["unknown"] += 1
                execution["child_wall_unknown"] += 1
                execution["rss_unknown"] += 1

            if not task["result_sha256"]:
                continue
            reviews = self.agent_reviews(task["id"])
            if not reviews:
                continue
            binding = result.get("binding") or {}
            experiment_id = spec.get("experiment_id") or result.get("experiment_id")
            dimensions = {
                "experiment_id": experiment_id,
                "mode": result.get("mode", "unknown"),
                "model": (result.get("provider") or {}).get("model") or "unknown",
                "prompt_version": result.get("prompt_version", "unknown"),
                "tool_policy_version": result.get("tool_policy_version", "unknown"),
            }
            key = tuple(dimensions[name] or "" for name in
                        ("experiment_id", "mode", "model", "prompt_version", "tool_policy_version"))
            group = groups.setdefault(key, {
                **dimensions, "operation_ids": set(), "candidate_ids": set(), "reviews": [],
                "usefulness": {"useful": 0, "partially_useful": 0, "not_useful": 0, "unsafe": 0},
                "citation_accuracy": {"all_accurate": 0, "some_incorrect": 0, "mostly_incorrect": 0, "not_checked": 0},
                "claim_support": {"supported": 0, "partially_supported": 0, "unsupported": 0,
                                  "unverifiable": 0, "not_reviewed": 0},
            })
            group["operation_ids"].add(task["id"])
            candidate_key = (binding.get("repository"), binding.get("commit"),
                             binding.get("candidate_id", "unknown"))
            group["candidate_ids"].add(candidate_key)
            for review in reviews:
                group["reviews"].append(review)
                group["usefulness"][review["usefulness"]] += 1
                group["citation_accuracy"][review["citation_accuracy"]] += 1
                claims = (result.get("agent_assessment") or {}).get("supported_claims", [])
                adjudications = review.get("claim_adjudications")
                adjudications = adjudications if isinstance(adjudications, list) else []
                by_index = {item.get("claim_index"): item.get("disposition")
                            for item in adjudications if isinstance(item, dict)}
                allowed = {"supported", "partially_supported", "unsupported", "unverifiable"}
                for claim_index in range(len(claims)):
                    disposition = by_index.get(claim_index)
                    if disposition in allowed:
                        group["claim_support"][disposition] += 1
                    else:
                        group["claim_support"]["not_reviewed"] += 1

            # Pair only explicitly tagged runs of the same immutable candidate,
            # provider model and prompt/tool versions. Untagged history is not
            # silently presented as a controlled comparison.
            if experiment_id and dimensions["mode"] in {"single_shot", "tool_agent"}:
                pair_key = (experiment_id, dimensions["model"], dimensions["prompt_version"],
                            dimensions["tool_policy_version"], *candidate_key)
                pair = paired.setdefault(pair_key, {})
                arm = pair.setdefault(dimensions["mode"], {"operation_ids": set(), "reviews": []})
                arm["operation_ids"].add(task["id"])
                arm["reviews"].extend(reviews)

        output = []
        for key in sorted(groups):
            group = groups[key]
            times = [item["elapsed_seconds"] for item in group["reviews"] if item.get("elapsed_seconds") is not None]
            output.append({
                **{name: group[name] for name in ("experiment_id", "mode", "model", "prompt_version", "tool_policy_version")},
                "operation_count": len(group["operation_ids"]),
                "candidate_count": len(group["candidate_ids"]),
                "review_count": len(group["reviews"]),
                "usefulness": group["usefulness"],
                "citation_accuracy": group["citation_accuracy"],
                "claim_support": group["claim_support"],
                "median_elapsed_seconds": statistics.median(times) if times else None,
            })

        def arm_summary(arm):
            reviews = arm["reviews"]
            times = [item["elapsed_seconds"] for item in reviews if item.get("elapsed_seconds") is not None]
            usefulness = {"useful": 0, "partially_useful": 0, "not_useful": 0, "unsafe": 0}
            citation_accuracy = {"all_accurate": 0, "some_incorrect": 0, "mostly_incorrect": 0, "not_checked": 0}
            for item in reviews:
                usefulness[item["usefulness"]] += 1
                citation_accuracy[item["citation_accuracy"]] += 1
            return {
                "operation_count": len(arm["operation_ids"]), "review_count": len(reviews),
                "usefulness": usefulness, "citation_accuracy": citation_accuracy,
                "median_elapsed_seconds": statistics.median(times) if times else None,
            }

        def baseline_summary(items):
            if not items:
                return None
            dispositions = {"investigate": 0, "likely_noise": 0, "unknown": 0}
            for item in items:
                dispositions[item["disposition"]] += 1
            times = [item["elapsed_seconds"] for item in items if item.get("elapsed_seconds") is not None]
            obligation_dispositions = {"evidence_found": 0, "contrary_evidence": 0, "unresolved": 0}
            obligation_review_count = 0
            for item in items:
                reviews = item.get("obligation_reviews")
                if not isinstance(reviews, list):
                    continue
                for review in reviews:
                    if isinstance(review, dict) and review.get("disposition") in obligation_dispositions:
                        obligation_dispositions[review["disposition"]] += 1
                        obligation_review_count += 1
            return {"review_count": len(items), "dispositions": dispositions,
                    "obligation_review_count": obligation_review_count,
                    "obligation_dispositions": obligation_dispositions,
                    "median_elapsed_seconds": statistics.median(times) if times else None}

        paired_comparisons = []
        for key in sorted(paired):
            arms = paired[key]
            if not {"single_shot", "tool_agent"}.issubset(arms):
                continue
            experiment_id, model, prompt_version, tool_policy_version, repository, commit, candidate_id = key
            paired_comparisons.append({
                "experiment_id": experiment_id, "repository": repository, "commit": commit,
                "candidate_id": candidate_id, "model": model,
                "prompt_version": prompt_version, "tool_policy_version": tool_policy_version,
                "single_shot": arm_summary(arms["single_shot"]),
                "tool_agent": arm_summary(arms["tool_agent"]),
                "r0_static_baseline": baseline_summary(baseline_by_candidate.get((experiment_id, repository, commit, candidate_id), [])),
            })
        return {
            "execution_scope": "recent_200_agent_operations_execution_telemetry_only",
            "execution_accuracy_claim": False,
            "execution_limitation": "统计持久化任务状态、结构校验、受限修复与工具调用、Provider 完整返回的 Token、本地 Agent 子进程耗时和峰值 RSS。费用是已知费率下的估算，实际账单未核验；RSS 不含父 Worker、Docker 容器或 Provider 基础设施。上述执行指标和人工意见都不代表漏洞准确率、Precision、Recall 或独立真值。",
            "execution_groups": [{
                **{name: group[name] for name in ("mode", "provider", "endpoint_host", "model", "prompt_version", "tool_policy_version")},
                "runtime_conditions": {
                    "application_process": "local operation child process",
                    "provider_endpoint": ("local_loopback" if group["endpoint_host"] in {"localhost", "127.0.0.1", "::1"}
                                          else "configured_network_endpoint" if group["endpoint_host"] != "unknown" else "unknown"),
                    "docker_container_metrics": "not_measured",
                    "process_rss_scope": "operation child process high-water mark; excludes parent worker, Docker containers, and provider infrastructure",
                },
                "operation_count": len(group["operation_ids"]),
                "status_counts": group["status_counts"],
                "result_count": group["result_count"],
                "schema_validation": group["schema_validation"],
                "repair_operation_count": group["repair_operation_count"],
                "repair_attempts": group["repair_attempts"],
                "tool_calls": group["tool_calls"],
                "tool_trace_operation_count": group["tool_trace_operation_count"],
                "model_tool_calls_skipped": group["model_tool_calls_skipped"],
                "usage": group["usage"],
                "token_usage": group["token_usage"],
                "cost_estimate_status_counts": group["cost_estimate_status_counts"],
                "cost_estimate_aggregates": [{
                    "status": bucket["status"], "rate_card_id": bucket["rate_card_id"],
                    "currency": bucket["currency"], "alternative_currency": bucket["alternative_currency"],
                    "rate_source_url": bucket["rate_source_url"],
                    "operation_count": bucket["operation_count"],
                    "amounts": {name: format(value.quantize(Decimal("0.00000001")), "f")
                                for name, value in bucket["amounts"].items()},
                    "amount_counts": bucket["amount_counts"],
                    "actual_charge_verified": False,
                } for _, bucket in sorted(group["cost_estimate_aggregates"].items())],
                "wall_time": {"measured_operation_count": len(group["wall_seconds"]),
                              "unknown_operation_count": group["wall_unknown"],
                              "median_seconds": statistics.median(group["wall_seconds"]) if group["wall_seconds"] else None,
                              "maximum_seconds": max(group["wall_seconds"]) if group["wall_seconds"] else None},
                "child_execution_time": {"measured_operation_count": len(group["child_execution_seconds"]),
                                          "unknown_operation_count": group["child_wall_unknown"],
                                          "median_seconds": statistics.median(group["child_execution_seconds"]) if group["child_execution_seconds"] else None},
                "process_peak_rss": {"measured_operation_count": len(group["process_peak_rss_bytes"]),
                                     "unknown_operation_count": group["rss_unknown"],
                                     "median_bytes": statistics.median(group["process_peak_rss_bytes"]) if group["process_peak_rss_bytes"] else None,
                                     "maximum_bytes": max(group["process_peak_rss_bytes"]) if group["process_peak_rss_bytes"] else None},
            } for _, group in sorted(execution_groups.items())],
            "scope": "operator_feedback_only",
            "accuracy_claim": False,
            "paired_comparison_scope": "matched_candidate_operator_feedback_only",
            "limitation": "Self-reported reviews measure perceived utility and citation quality, not vulnerability precision, recall, or ground truth. R1/R2 pairs are descriptive, not randomized causal estimates; R0 static-only human triage is shown when recorded before the LLM run; it is still a reviewer opinion, not ground truth.",
            "groups": output,
            "paired_comparisons": paired_comparisons,
            "r0_baseline_reviews": baseline_reviews,
        }
    def record_agent_review(self, key, record):
        task = self.get(key)
        if task["kind"] != "agent_investigation" or task["status"] not in {"completed", "completed_with_limitations"}:
            raise ValueError("human Agent review requires a completed Agent investigation")
        result = self.result(key)
        if result.get("vulnerability_state") != "candidate" or result.get("validated_vulnerability") != 0:
            raise ValueError("Agent review cannot be attached to a promoted vulnerability result")
        claims = (result.get("agent_assessment") or {}).get("supported_claims", [])
        adjudications = record.get("claim_adjudications", [])
        if not isinstance(adjudications, list) or len(adjudications) > 30:
            raise ValueError("invalid human claim adjudications")
        if adjudications and len(adjudications) != len(claims):
            raise ValueError("human claim adjudications must cover every supported claim")
        indices = []
        allowed = {"supported", "partially_supported", "unsupported", "unverifiable"}
        for item in adjudications:
            if (not isinstance(item, dict) or set(item) != {"claim_index", "disposition"}
                    or not isinstance(item.get("claim_index"), int)
                    or isinstance(item.get("claim_index"), bool)
                    or item.get("disposition") not in allowed):
                raise ValueError("invalid human claim adjudication")
            index = item["claim_index"]
            if index < 0 or index >= len(claims) or index in indices:
                raise ValueError("human claim indices must be unique and in range")
            indices.append(index)
        if adjudications and set(indices) != set(range(len(claims))):
            raise ValueError("human claim adjudications must cover every supported claim")
        review = {
            **record,
            "claim_review_scope": ("claim_evidence_support_only" if claims and adjudications
                                   else "not_reviewed" if claims else "no_model_claims"),
            "operation_id": key,
            "result_sha256": task["result_sha256"],
            "binding": result.get("binding"),
            "model_assessment": result.get("agent_assessment", {}).get("assessment", "unknown"),
            "review_scope": "model_triage_quality_only",
        }
        encoded = json.dumps(review, ensure_ascii=False, sort_keys=True)
        if len(encoded.encode("utf-8")) > 8192:
            raise ValueError("Agent human review is too large for the append-only audit event")
        self.event(key, "agent_human_review", encoded)
        return self.agent_reviews(key)[-1]

    def agent_reviews(self, key):
        task = self.get(key)
        if task["kind"] != "agent_investigation":
            raise ValueError("human Agent review exists only for Agent investigations")
        reviews = []
        for event in self.events(key):
            if event["stage"] == "agent_human_review":
                record = json.loads(event["message"])
                reviews.append({"created_at": event["created_at"], **record})
        return reviews

    def create_agent_blind_session(self, experiment_id, packets):
        """Persist shuffled, arm-redacted packets with a private operation/result mapping."""
        if not experiment_id or len(packets) < 2 or len(packets) > 20:
            raise ValueError("blind review requires 1-10 complete R1/R2 candidate pairs")
        session_id = uuid.uuid4().hex
        order = list(packets)
        import random
        random.SystemRandom().shuffle(order)
        stamp = now()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT INTO agent_blind_sessions(id,experiment_id,state,created_at) VALUES(?,?,?,?)",
                       (session_id, experiment_id, "open", stamp))
            for index, item in enumerate(order):
                item_id = uuid.uuid4().hex
                packet_text = json.dumps(item["packet"], sort_keys=True, ensure_ascii=False, separators=(",", ":"))
                packet_digest = hashlib.sha256(packet_text.encode("utf-8")).hexdigest()
                db.execute("""INSERT INTO agent_blind_items
                  (id,session_id,operation_id,result_sha256,item_order,packet,packet_sha256)
                  VALUES(?,?,?,?,?,?,?)""",
                  (item_id, session_id, item["operation_id"], item["result_sha256"], index,
                   packet_text, packet_digest))
        return {"id": session_id, "experiment_id": experiment_id, "state": "open",
                "item_count": len(order), "created_at": stamp}

    def agent_blind_session(self, session_id, include_packets=False):
        with self.store.connect() as db:
            session = db.execute("SELECT * FROM agent_blind_sessions WHERE id=?", (session_id,)).fetchone()
            if session is None:
                raise KeyError("blind review session not found")
            items = db.execute("""SELECT i.*,r.record AS review_record,r.record_sha256 AS review_sha256
                FROM agent_blind_items i LEFT JOIN agent_blind_reviews r
                  ON r.session_id=i.session_id AND r.item_id=i.id
                WHERE i.session_id=? ORDER BY i.item_order""", (session_id,)).fetchall()
        result = {"id": session["id"], "experiment_id": session["experiment_id"],
                  "state": session["state"], "created_at": session["created_at"],
                  "closed_at": session["closed_at"], "items": []}
        metric_packets = {}
        for item in items:
            packet = json.loads(item["packet"])
            if hashlib.sha256(json.dumps(packet, sort_keys=True, ensure_ascii=False,
                                         separators=(",", ":")).encode("utf-8")).hexdigest() != item["packet_sha256"]:
                raise ValueError("blind review packet integrity mismatch")
            metric_packets[item["id"]] = packet
            entry = {"blind_item_id": item["id"], "order": item["item_order"],
                     "packet_sha256": item["packet_sha256"],
                     "reviewed": item["review_record"] is not None}
            if include_packets:
                entry["packet"] = packet
            if item["review_record"] is not None:
                if hashlib.sha256(item["review_record"].encode("utf-8")).hexdigest() != item["review_sha256"]:
                    raise ValueError("blind review integrity mismatch")
                if session["state"] == "closed":
                    entry["review"] = json.loads(item["review_record"])
                    entry["review_sha256"] = item["review_sha256"]
            if session["state"] == "closed":
                operation = self.result(item["operation_id"])
                entry["unblinded"] = {"operation_id": item["operation_id"],
                    "result_sha256": item["result_sha256"], "mode": operation.get("mode", "unknown"),
                    "model": (operation.get("provider") or {}).get("model", "unknown"),
                    "binding": operation.get("binding")}
            result["items"].append(entry)
        if session["state"] == "closed":
            reviewed = [item for item in result["items"] if item.get("review")]
            guessed = [item for item in reviewed
                       if item["review"].get("guessed_arm") in {"single_shot", "tool_agent"}]
            correct = sum(item["review"].get("guessed_arm") == item["unblinded"].get("mode")
                          for item in guessed)
            confidences = [item["review"].get("guess_confidence") for item in guessed
                           if item["review"].get("guess_confidence") is not None]
            result["blind_guess_summary"] = {
                "reviewed_items": len(reviewed),
                "guessed_items": len(guessed),
                "unknown_items": len(reviewed) - len(guessed),
                "correct_guesses": correct,
                "incorrect_guesses": len(guessed) - correct,
                "accuracy_when_guessed": correct / len(guessed) if guessed else None,
                "mean_confidence_when_guessed": round(statistics.mean(confidences), 1) if confidences else None,
            }
            arm_feedback = {}
            for mode in ("single_shot", "tool_agent"):
                arm_items = [item for item in reviewed if item["unblinded"].get("mode") == mode]
                reviews = [item["review"] for item in arm_items]
                def count_values(values, allowed):
                    counts = {value: 0 for value in allowed}
                    for value in values:
                        counts[value if value in counts else allowed[-1]] += 1
                    return counts
                times = [review["elapsed_seconds"] for review in reviews
                         if review.get("elapsed_seconds") is not None]
                human_obligation_reviews = 0
                exact_disposition_matches = 0
                disposition_differences = 0
                unreviewed_obligations = 0
                claim_counts = {"supported": 0, "partially_supported": 0,
                                "unsupported": 0, "unverifiable": 0}
                claim_reviews = 0
                claim_unreviewed = 0
                for item in arm_items:
                    packet = metric_packets.get(item["blind_item_id"]) or {}
                    obligations = (packet.get("candidate") or {}).get("evidence_obligations", [])
                    model_reviews = (packet.get("assessment") or {}).get("obligation_reviews", [])
                    model_by_index = {entry.get("obligation_index"): entry.get("disposition")
                                      for entry in model_reviews if isinstance(entry, dict)}
                    human_reviews = item["review"].get("obligation_adjudications", [])
                    if not human_reviews:
                        unreviewed_obligations += len(obligations)
                        continue
                    human_by_index = {entry["obligation_index"]: entry["disposition"]
                                      for entry in human_reviews}
                    for index in range(len(obligations)):
                        if index not in human_by_index or index not in model_by_index:
                            unreviewed_obligations += 1
                            continue
                        human_obligation_reviews += 1
                        if human_by_index[index] == model_by_index[index]:
                            exact_disposition_matches += 1
                        else:
                            disposition_differences += 1
                    claims = (packet.get("assessment") or {}).get("supported_claims", [])
                    human_claims = item["review"].get("claim_adjudications", [])
                    human_claim_by_index = {entry["claim_index"]: entry["disposition"]
                                            for entry in human_claims}
                    for index in range(len(claims)):
                        disposition = human_claim_by_index.get(index)
                        if disposition not in claim_counts:
                            claim_unreviewed += 1
                            continue
                        claim_counts[disposition] += 1
                        claim_reviews += 1
                arm_feedback[mode] = {
                    "review_count": len(reviews),
                    "obligation_disposition_concordance": {
                        "reviewed_obligations": human_obligation_reviews,
                        "exact_matches": exact_disposition_matches,
                        "differences": disposition_differences,
                        "not_reviewed": unreviewed_obligations,
                        "interpretation": "Human/model disposition agreement on source obligations; not vulnerability ground truth.",
                    },
                    "claim_evidence_support": {
                        **claim_counts,
                        "reviewed_claims": claim_reviews,
                        "not_reviewed": claim_unreviewed,
                        "interpretation": "Human review of whether each cited evidence set semantically supports its model claim; not vulnerability ground truth, precision, or recall.",
                    },
                    "post_review_disposition": count_values(
                        [review.get("post_review_disposition") for review in reviews],
                        ("investigate", "likely_noise", "unknown", "not_recorded")),
                    "usefulness": count_values(
                        [review.get("usefulness") for review in reviews],
                        ("useful", "partially_useful", "not_useful", "unsafe", "not_recorded")),
                    "citation_accuracy": count_values(
                        [review.get("citation_accuracy") for review in reviews],
                        ("all_accurate", "some_incorrect", "mostly_incorrect", "not_checked", "not_recorded")),
                    "median_elapsed_seconds": statistics.median(times) if times else None,
                }
            result["operator_review_by_arm"] = arm_feedback
        return result

    def agent_blind_review_agreement(self, session_ids):
        if not isinstance(session_ids, list) or not 2 <= len(session_ids) <= 10:
            raise ValueError("review agreement requires 2-10 closed blind sessions")
        if len(session_ids) != len(set(session_ids)):
            raise ValueError("review agreement session IDs must be unique")
        sessions = [self.agent_blind_session(session_id) for session_id in session_ids]
        if any(session["state"] != "closed" for session in sessions):
            raise ValueError("all blind sessions must be closed before agreement analysis")
        experiment_ids = {session["experiment_id"] for session in sessions}
        if len(experiment_ids) != 1:
            raise ValueError("blind sessions must belong to the same experiment")

        def by_operation(session):
            output = {}
            for item in session["items"]:
                operation_id = item["unblinded"]["operation_id"]
                if operation_id in output:
                    raise ValueError("blind session contains duplicate operation results")
                output[operation_id] = item
            return output

        indexed = [by_operation(session) for session in sessions]
        expected = set(indexed[0])
        if not expected or any(set(items) != expected for items in indexed[1:]):
            raise ValueError("blind sessions must review the exact same operation results")
        matched = []
        for operation_id in sorted(expected):
            items = [mapping[operation_id] for mapping in indexed]
            result_hashes = {item["unblinded"]["result_sha256"] for item in items}
            packet_hashes = {item["packet_sha256"] for item in items}
            if len(result_hashes) != 1 or len(packet_hashes) != 1:
                raise ValueError("blind sessions do not share the same immutable result and packet")
            if any(not item.get("review") for item in items):
                raise ValueError("every matched item must have a closed reviewer record")
            reviewer_labels = [str(item["review"].get("reviewer", "")).strip().casefold()
                               for item in items]
            if "" in reviewer_labels or len(reviewer_labels) != len(set(reviewer_labels)):
                raise ValueError("each result needs distinct non-empty self-reported reviewer labels")
            matched.append(items)

        def agreement(records):
            pair_total = 0
            pair_matches = 0
            comparable_items = 0
            unanimous_items = 0
            disagreement_items = 0
            for ratings in records:
                values = [value for value in ratings if value is not None]
                pairs = len(values) * (len(values) - 1) // 2
                if not pairs:
                    continue
                comparable_items += 1
                pair_total += pairs
                equal_pairs = sum(values[left] == values[right]
                                  for left in range(len(values)) for right in range(left + 1, len(values)))
                pair_matches += equal_pairs
                if equal_pairs == pairs:
                    unanimous_items += 1
                else:
                    disagreement_items += 1
            return {"comparable_items": comparable_items, "unanimous_items": unanimous_items,
                    "disagreement_items": disagreement_items, "reviewer_pairs": pair_total,
                    "matching_pairs": pair_matches,
                    "pairwise_agreement": pair_matches / pair_total if pair_total else None}

        per_arm = {}
        for mode in ("single_shot", "tool_agent"):
            arm_items = [[item for item in items if item["unblinded"].get("mode") == mode]
                         for items in matched]
            mode_rows = [next(iter(rows)) for rows in arm_items if rows]
            fields = {}
            for field in ("usefulness", "citation_accuracy", "post_review_disposition"):
                fields[field] = agreement([[item["review"].get(field) for item in rows]
                                           for rows in arm_items if rows])
            obligation_records = {}
            claim_records = {}
            for rows in arm_items:
                if not rows:
                    continue
                expected_obligations = max((len(item["review"].get("obligation_adjudications", []))
                                            for item in rows), default=0)
                expected_claims = max((len(item["review"].get("claim_adjudications", []))
                                       for item in rows), default=0)
                for index in range(expected_obligations):
                    labels = []
                    for item in rows:
                        adjudications = item["review"].get("obligation_adjudications", [])
                        match = next((entry for entry in adjudications
                                      if entry.get("obligation_index") == index), None)
                        labels.append(match.get("disposition") if match else None)
                    obligation_records.setdefault(index, []).append(labels)
                for index in range(expected_claims):
                    labels = []
                    for item in rows:
                        adjudications = item["review"].get("claim_adjudications", [])
                        match = next((entry for entry in adjudications
                                      if entry.get("claim_index") == index), None)
                        labels.append(match.get("disposition") if match else None)
                    claim_records.setdefault(index, []).append(labels)
            per_arm[mode] = {
                "reviewed_operations": len(mode_rows),
                "reviewer_count": len(sessions),
                "unique_reviewer_labels_min": min(
                    (len({item["review"].get("reviewer") for item in rows}) for rows in arm_items if rows),
                    default=0),
                "unique_reviewer_labels_max": max(
                    (len({item["review"].get("reviewer") for item in rows}) for rows in arm_items if rows),
                    default=0),
                "agreement": fields,
                "evidence_obligation_agreement": {
                    str(index): agreement(records) for index, records in obligation_records.items()
                    if isinstance(index, int)},
                "claim_evidence_support_agreement": {
                    str(index): agreement(records) for index, records in claim_records.items()
                    if isinstance(index, int)},
            }

        report = {"schema_version": 1, "experiment_id": sessions[0]["experiment_id"],
                "blind_session_count": len(sessions), "matched_operation_count": len(matched[0]),
                "sessions": [{"id": session["id"], "closed_at": session["closed_at"]}
                             for session in sessions],
                "per_arm": per_arm,
                "interpretation": "Pairwise agreement among reviewer labels on blinded Agent triage; not vulnerability truth, precision, recall, or proof that reviewers were independent. Agreement is descriptive and chance-corrected statistics are not computed."}
        canonical = json.dumps(report, sort_keys=True, ensure_ascii=False,
                               separators=(",", ":")).encode("utf-8")
        report["report_sha256"] = hashlib.sha256(canonical).hexdigest()
        return report

    def agent_blind_export(self, session_id):
        session = self.agent_blind_session(session_id, include_packets=True)
        if session["state"] != "open":
            raise ValueError("only open blind review sessions can be exported")
        pending = [item for item in session["items"] if not item["reviewed"]]
        if not pending:
            raise ValueError("all items in this blind review session are already reviewed")
        return {"schema_version": 1, "blind_session_id": session["id"],
                "items": [{"blind_item_id": item["blind_item_id"], "order": item["order"],
                           "packet_sha256": item["packet_sha256"], "packet": item["packet"]}
                          for item in pending]}

    def agent_blind_evidence_bundle(self, session_id):
        session = self.agent_blind_session(session_id, include_packets=True)
        if session["state"] != "closed":
            raise ValueError("evidence bundle requires a closed blind review session")
        items = []
        candidate_keys = set()
        for item in session["items"]:
            operation_id = item["unblinded"]["operation_id"]
            task = self.get(operation_id)
            result = self.result(operation_id)
            if task["result_sha256"] != item["unblinded"]["result_sha256"]:
                raise ValueError("Agent result integrity mismatch in blind review session")
            binding = result.get("binding") or {}
            candidate_keys.add((binding.get("repository"), binding.get("commit"),
                                binding.get("report_sha256"), binding.get("candidate_id"),
                                binding.get("source_sha256")))
            items.append({
                "blind_item_id": item["blind_item_id"],
                "order": item["order"],
                "packet_sha256": item["packet_sha256"],
                "packet": item["packet"],
                "review": item["review"],
                "review_sha256": item["review_sha256"],
                "operation_id": operation_id,
                "result_sha256": task["result_sha256"],
                "operation_spec": task["spec"],
                "result": result,
            })
        baselines = self.agent_baseline_reviews(session["experiment_id"])
        matched_baselines = []
        for baseline in baselines:
            key = (baseline.get("repository"), baseline.get("commit"),
                   baseline.get("report_sha256"), baseline.get("candidate_id"),
                   baseline.get("source_sha256"))
            if key in candidate_keys:
                matched_baselines.append(baseline)
        bundle = {
            "schema_version": 1,
            "bundle_type": "ohscanner_agent_blind_evidence",
            "blind_session": {key: session[key] for key in
                              ("id", "experiment_id", "state", "created_at", "closed_at",
                               "blind_guess_summary")},
            "items": items,
            "r0_baseline_reviews": matched_baselines,
            "interpretation_limits": [
                "This bundle records source-bound Agent triage and blinded operator feedback.",
                "Operator reviews are not vulnerability ground truth, precision, or recall.",
                "Candidate and validated_vulnerability fields retain their original evidence state.",
            ],
        }
        canonical = json.dumps(bundle, ensure_ascii=False, sort_keys=True,
                               separators=(",", ":")).encode("utf-8")
        bundle["bundle_sha256"] = hashlib.sha256(canonical).hexdigest()
        return bundle

    def import_agent_blind_reviews(self, session_id, reviews):
        if not reviews or len(reviews) > 20:
            raise ValueError("blind review import requires 1-20 review records")
        ids = [item["blind_item_id"] for item in reviews]
        if len(ids) != len(set(ids)):
            raise ValueError("blind review import contains duplicate item IDs")
        encoded_records = []
        for item in reviews:
            record = item["record"]
            encoded = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
            if len(encoded.encode("utf-8")) > 8192:
                raise ValueError("blind Agent review is too large")
            encoded_records.append((item["blind_item_id"], record, encoded,
                                   hashlib.sha256(encoded.encode("utf-8")).hexdigest()))
        stamp = now()
        inserted = []
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            session = db.execute("SELECT * FROM agent_blind_sessions WHERE id=?", (session_id,)).fetchone()
            if session is None:
                raise KeyError("blind review session not found")
            if session["state"] != "open":
                raise ValueError("blind review session is closed")
            for item_id, record, encoded, digest in encoded_records:
                item = db.execute("SELECT * FROM agent_blind_items WHERE id=? AND session_id=?",
                                  (item_id, session_id)).fetchone()
                if item is None:
                    raise KeyError("blind review item not found")
                if record.get("packet_sha256") != item["packet_sha256"]:
                    raise ValueError("review packet hash does not match the exported blind item")
                adjudications = record.get("obligation_adjudications", [])
                claim_adjudications = record.get("claim_adjudications", [])
                packet = json.loads(item["packet"])
                obligations = (packet.get("candidate") or {}).get("evidence_obligations", [])
                model_reviews = (packet.get("assessment") or {}).get("obligation_reviews", [])
                claims = (packet.get("assessment") or {}).get("supported_claims", [])
                if not isinstance(adjudications, list) or len(adjudications) > 30:
                    raise ValueError("invalid evidence obligation adjudications")
                if model_reviews and len(adjudications) != len(obligations):
                    raise ValueError("human adjudications must cover every supplied evidence obligation")
                if adjudications:
                    if len(adjudications) != len(obligations):
                        raise ValueError("human adjudications must cover every supplied evidence obligation")
                    indices = []
                    for adjudication in adjudications:
                        if (not isinstance(adjudication, dict)
                                or set(adjudication) != {"obligation_index", "disposition"}
                                or not isinstance(adjudication.get("obligation_index"), int)
                                or isinstance(adjudication.get("obligation_index"), bool)
                                or adjudication.get("disposition") not in {"evidence_found", "contrary_evidence", "unresolved"}):
                            raise ValueError("invalid evidence obligation adjudication")
                        index = adjudication["obligation_index"]
                        if index < 0 or index >= len(obligations) or index in indices:
                            raise ValueError("human evidence obligation indices must be unique and in range")
                        indices.append(index)
                    if set(indices) != set(range(len(obligations))):
                        raise ValueError("human adjudications must cover every supplied evidence obligation")
                if (not isinstance(claim_adjudications, list) or len(claim_adjudications) > 30
                        or len(claim_adjudications) != len(claims)):
                    raise ValueError("human claim adjudications must cover every supported claim")
                claim_indices = []
                for adjudication in claim_adjudications:
                    if (not isinstance(adjudication, dict)
                            or set(adjudication) != {"claim_index", "disposition"}
                            or not isinstance(adjudication.get("claim_index"), int)
                            or isinstance(adjudication.get("claim_index"), bool)
                            or adjudication.get("disposition") not in {"supported", "partially_supported", "unsupported", "unverifiable"}):
                        raise ValueError("invalid supported claim adjudication")
                    index = adjudication["claim_index"]
                    if index < 0 or index >= len(claims) or index in claim_indices:
                        raise ValueError("human supported claim indices must be unique and in range")
                    claim_indices.append(index)
                if set(claim_indices) != set(range(len(claims))):
                    raise ValueError("human claim adjudications must cover every supported claim")
                if db.execute("SELECT 1 FROM agent_blind_reviews WHERE session_id=? AND item_id=?",
                              (session_id, item_id)).fetchone():
                    raise ValueError("blind review for this item already exists")
                db.execute("""INSERT INTO agent_blind_reviews
                    (session_id,item_id,result_sha256,record,record_sha256,created_at)
                    VALUES(?,?,?,?,?,?)""",
                    (session_id, item_id, item["result_sha256"], encoded, digest, stamp))
                audit_record = {**record, "operation_id": item["operation_id"],
                    "result_sha256": item["result_sha256"], "blind_session_id": session_id,
                    "blind_item_id": item_id, "review_scope": "blinded_agent_triage_quality_only"}
                db.execute("INSERT INTO operation_events(operation_id,created_at,stage,message) VALUES(?,?,?,?)",
                    (item["operation_id"], stamp, "agent_human_review",
                     json.dumps(audit_record, ensure_ascii=False, sort_keys=True)))
                inserted.append({"blind_item_id": item_id, "result_sha256": item["result_sha256"],
                                 "record_sha256": digest})
        return {"blind_session_id": session_id, "imported_count": len(inserted), "items": inserted}

    def close_agent_blind_session(self, session_id):
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            session = db.execute("SELECT * FROM agent_blind_sessions WHERE id=?", (session_id,)).fetchone()
            if session is None:
                raise KeyError("blind review session not found")
            if session["state"] != "open":
                raise ValueError("blind review session is already closed")
            items = db.execute("""SELECT i.*,r.record_sha256 AS review_sha256
                FROM agent_blind_items i LEFT JOIN agent_blind_reviews r
                  ON r.session_id=i.session_id AND r.item_id=i.id
                WHERE i.session_id=? ORDER BY i.item_order""", (session_id,)).fetchall()
            if not items or any(item["review_sha256"] is None for item in items):
                raise ValueError("all blind items must be reviewed before unblinding")
            stamp = now()
            db.execute("UPDATE agent_blind_sessions SET state='closed',closed_at=? WHERE id=?",
                       (stamp, session_id))
        return self.agent_blind_session(session_id)

    def assessment(self, case_id, record):
        with self.store.connect() as db:
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise KeyError("case not found")
            db.execute("INSERT INTO case_assessments(case_id,record,created_at) VALUES(?,?,?)",
                       (case_id, json.dumps(record, ensure_ascii=False), now()))
        return self.assessments(case_id)

    def assessments(self, case_id):
        with self.store.connect() as db:
            return [{"id": r["id"], "created_at": r["created_at"], **json.loads(r["record"])}
                    for r in db.execute("SELECT * FROM case_assessments WHERE case_id=? ORDER BY id", (case_id,))]

    def retry_repository_import(self, key):
        """Queue a new attempt for a failed import without mutating its original plan."""
        retryable = {"failed", "interrupted", "timed_out"}
        new_key = uuid.uuid4().hex
        stamp = now()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            original = self.row(db.execute(
                "SELECT * FROM operations WHERE id=?", (key,)).fetchone())
            if original["kind"] != "repository_import_scan":
                raise ValueError("only repository import operations can be retried here")
            existing = []
            for row in db.execute("SELECT * FROM operations WHERE kind='repository_import_scan'"):
                spec = json.loads(row["spec"])
                if spec.get("retry_of") == key:
                    existing.append(self.row(row))
            if existing:
                # Repeated HTTP submissions return the same attempt, including after it
                # completes. To deliberately retry again, submit the latest failed attempt.
                retry = existing[0]
                retry["retry_reused"] = True
                return retry
            if original["status"] not in retryable:
                raise ValueError("repository import can be retried only after failed, interrupted, or timed-out status")
            active = db.execute(
                "SELECT count(*) FROM operations WHERE status IN ('queued','running') AND kind!='candidate_review_batch'").fetchone()[0]
            if active >= 100:
                raise ValueError("operation queue full")
            retry_spec = {**original["spec"], "retry_of": key}
            db.execute("INSERT INTO operations(id,kind,spec,status,created_at) VALUES(?,?,?,?,?)",
                       (new_key, "repository_import_scan", json.dumps(retry_spec, sort_keys=True),
                        "queued", stamp))
            db.execute("INSERT INTO operation_events(operation_id,created_at,stage,message) VALUES(?,?,?,?)",
                       (new_key, stamp, "retry_queued", "Explicit retry of failed repository import " + key))
        return self.get(new_key)
