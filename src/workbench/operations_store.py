"""Incremental operation queue; old scan artifacts and identities stay untouched."""
import fcntl
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid
from .store import now

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
        self.store.migrate_investigation_drafts()

    def directory(self, key):
        if len(key) != 32 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("invalid operation ID")
        return self.store.root / "operations" / key

    def create(self, kind, spec):
        if kind not in {"source_sync", "revision_range", "version_matrix", "validation", "investigation"}:
            raise ValueError("unknown operation kind")
        key = uuid.uuid4().hex
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT count(*) FROM operations WHERE status IN ('queued','running')").fetchone()[0] >= 100:
                raise ValueError("operation queue full")
            db.execute("INSERT INTO operations(id,kind,spec,status,created_at) VALUES(?,?,?,?,?)",
                       (key, kind, json.dumps(spec, sort_keys=True), "queued", now()))
        self.event(key, "queued", "Immutable operation plan saved")
        return self.get(key)

    def create_with_scans(self, kind, spec, repository_id, scan_specs):
        """Create an operation and its immutable endpoint jobs in one DB transaction."""
        if kind not in {"revision_range", "version_matrix"} or not scan_specs:
            raise ValueError("invalid scan operation")
        key = uuid.uuid4().hex
        job_ids = [uuid.uuid4().hex for _ in scan_specs]
        spec = {**spec, "scan_ids": job_ids}
        stamp = now()
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
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
            row = db.execute("SELECT id FROM operations WHERE status='queued' AND kind " + sign + " 'validation' ORDER BY created_at LIMIT 1").fetchone()
            if not row:
                return None
            db.execute("UPDATE operations SET status='running',started_at=? WHERE id=?", (now(), row[0]))
            return self.row(db.execute("SELECT * FROM operations WHERE id=?", (row[0],)).fetchone())

    def cancel(self, key):
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.row(db.execute("SELECT * FROM operations WHERE id=?", (key,)).fetchone())
            if row["status"] not in END:
                db.execute("UPDATE operations SET cancel_requested=1 WHERE id=?", (key,))
                if row["status"] == "queued":
                    db.execute("UPDATE operations SET status='cancelled',finished_at=? WHERE id=?", (now(), key))
        # Cancel owned endpoint scans, never unrelated jobs.
        for job in row["spec"].get("scan_ids", []):
            self.store.cancel(job)
        return self.get(key)

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
