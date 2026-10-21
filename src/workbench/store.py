"""Transactional single-machine queue and append-only review history."""

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import fcntl
import json
from pathlib import Path
import re
import sqlite3
import uuid

TERMINAL = {
    "completed",
    "completed_with_limitations",
    "failed",
    "cancelled",
    "interrupted",
    "timed_out",
}


def now():
    return datetime.now(timezone.utc).isoformat()


class Store:
    def __init__(self, data_dir: Path):
        self.root = data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "workbench.sqlite3"
        # The API and three Worker processes can start together. Serialize first
        # schema/WAL initialization before any process begins polling the queues.
        with (data_dir / "store-init.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            with self.connect() as db:
                journal_mode = db.execute("PRAGMA journal_mode").fetchone()[0].lower()
                if journal_mode != "wal":
                    db.execute("PRAGMA journal_mode=WAL")
                db.executescript("""
                CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);
                INSERT OR IGNORE INTO schema_migrations VALUES(1);
                CREATE TABLE IF NOT EXISTS repositories(
                  id TEXT PRIMARY KEY, name TEXT NOT NULL, path TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS jobs(
                  id TEXT PRIMARY KEY, repository_id TEXT NOT NULL REFERENCES repositories(id),
                  spec TEXT NOT NULL, status TEXT NOT NULL, stage TEXT NOT NULL,
                  created_at TEXT NOT NULL, started_at TEXT, finished_at TEXT,
                  cancel_requested INTEGER NOT NULL DEFAULT 0, error TEXT, worker_pid INTEGER,
                  report_sha256 TEXT, elapsed_seconds REAL);
                CREATE TABLE IF NOT EXISTS events(
                  id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL REFERENCES jobs(id),
                  created_at TEXT NOT NULL, stage TEXT NOT NULL, message TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS reviews(
                  id INTEGER PRIMARY KEY AUTOINCREMENT, job_id TEXT NOT NULL REFERENCES jobs(id),
                  candidate_id TEXT NOT NULL, status TEXT NOT NULL, reviewer TEXT NOT NULL,
                  notes TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS review_lookup ON reviews(job_id, candidate_id, id);
                CREATE TABLE IF NOT EXISTS cases(
                  id TEXT PRIMARY KEY, title TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS case_links(
                  case_id TEXT NOT NULL REFERENCES cases(id), job_id TEXT NOT NULL REFERENCES jobs(id),
                  candidate_id TEXT NOT NULL, rationale TEXT NOT NULL,
                  PRIMARY KEY(case_id,job_id,candidate_id));
                CREATE INDEX IF NOT EXISTS job_queue ON jobs(status, created_at);
                CREATE TABLE IF NOT EXISTS source_evidence(
                  id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES jobs(id),
                  candidate_id TEXT NOT NULL, record TEXT NOT NULL, created_at TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS evidence_lookup ON source_evidence(job_id,candidate_id);
                INSERT OR IGNORE INTO schema_migrations VALUES(2);
                """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def job_row(row):
        if row is None:
            raise KeyError("job not found")
        item = dict(row)
        item["spec"] = json.loads(item["spec"])
        item["cancel_requested"] = bool(item["cancel_requested"])
        return item

    def repositories(self):
        with self.connect() as db:
            return [
                dict(r)
                for r in db.execute("SELECT * FROM repositories ORDER BY created_at")
            ]

    def repository(self, key):
        with self.connect() as db:
            row = db.execute("SELECT * FROM repositories WHERE id=?", (key,)).fetchone()
            if row is None:
                raise KeyError("repository not found")
            return dict(row)

    def add_repository(self, name, path):
        key = uuid.uuid4().hex
        with self.connect() as db:
            db.execute(
                "INSERT INTO repositories VALUES(?,?,?,?)",
                (key, name, str(path), now()),
            )
        return self.repository(key)

    def create_job(self, repository_id, spec):
        key = uuid.uuid4().hex
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if (
                db.execute(
                    "SELECT count(*) FROM jobs WHERE status IN ('queued','running')"
                ).fetchone()[0]
                >= 100
            ):
                raise ValueError("queue capacity reached")
            db.execute(
                "INSERT INTO jobs(id,repository_id,spec,status,stage,created_at) VALUES(?,?,?,?,?,?)",
                (
                    key,
                    repository_id,
                    json.dumps(spec, sort_keys=True),
                    "queued",
                    "source_pinned",
                    now(),
                ),
            )
            db.execute(
                "INSERT INTO events(job_id,created_at,stage,message) VALUES(?,?,?,?)",
                (
                    key,
                    now(),
                    "source_pinned",
                    "Requested revision resolved to immutable commit/tree",
                ),
            )
            authorization = spec.get("triage_authorization")
            if isinstance(authorization, dict) and authorization.get("authorized") is True:
                digest = authorization.get("consent_sha256")
                snapshot = authorization.get("snapshot")
                if (not isinstance(digest, str) or len(digest) != 64
                        or not isinstance(snapshot, dict)):
                    raise ValueError("invalid task-level triage authorization snapshot")
                db.execute(
                    "INSERT INTO triage_authorizations(audit_id,consent_sha256,snapshot,created_at) VALUES(?,?,?,?)",
                    (key, digest, json.dumps(snapshot, sort_keys=True), now()),
                )
        return self.job(key)

    def triage_authorization(self, audit_id):
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM triage_authorizations WHERE audit_id=?", (audit_id,)
            ).fetchone()
        if row is None:
            return None
        item = dict(row)
        item["snapshot"] = json.loads(item["snapshot"])
        item["revoked"] = bool(item["revoked_at"])
        return item

    def revoke_triage_authorization(self, audit_id, expected_digest):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT consent_sha256,revoked_at FROM triage_authorizations WHERE audit_id=?",
                (audit_id,),
            ).fetchone()
            if row is None:
                raise KeyError("triage authorization not found")
            if row["consent_sha256"] != expected_digest:
                raise ValueError("triage authorization changed; reload before revoking")
            if row["revoked_at"] is None:
                stamp = now()
                db.execute(
                    "UPDATE triage_authorizations SET revoked_at=? WHERE audit_id=? AND revoked_at IS NULL",
                    (stamp, audit_id),
                )
                db.execute(
                    "INSERT INTO events(job_id,created_at,stage,message) VALUES(?,?,?,?)",
                    (audit_id, stamp, "triage_authorization_revoked",
                     "Task-level model source egress authorization revoked; pending bound investigations must stop"),
                )
        return self.triage_authorization(audit_id)

    def job(self, key):
        with self.connect() as db:
            return self.job_row(
                db.execute("SELECT * FROM jobs WHERE id=?", (key,)).fetchone()
            )

    def jobs(self):
        with self.connect() as db:
            return [
                self.job_row(r)
                for r in db.execute(
                    "SELECT * FROM jobs ORDER BY created_at DESC LIMIT 200"
                )
            ]

    def authorized_completed_jobs_missing_batch(self):
        """Return every durable authorized scan that needs idempotent triage recovery."""
        with self.connect() as db:
            rows = db.execute(
                "SELECT j.* FROM jobs j "
                "JOIN triage_authorizations a ON a.audit_id=j.id "
                "LEFT JOIN smart_triage_batches b ON b.audit_id=j.id "
                "AND b.report_sha256=j.report_sha256 AND b.authorization_sha256=a.consent_sha256 "
                "WHERE j.status IN ('completed','completed_with_limitations') "
                "AND j.report_sha256 IS NOT NULL AND a.revoked_at IS NULL AND b.id IS NULL "
                "ORDER BY j.created_at,j.id"
            ).fetchall()
        return [self.job_row(row) for row in rows]

    def event(self, key, stage, message):
        with self.connect() as db:
            db.execute("UPDATE jobs SET stage=? WHERE id=?", (stage, key))
            db.execute(
                "INSERT INTO events(job_id,created_at,stage,message) VALUES(?,?,?,?)",
                (key, now(), stage, message[:4000]),
            )

    def events(self, key, after=0):
        self.job(key)
        with self.connect() as db:
            return [
                dict(r)
                for r in db.execute(
                    "SELECT * FROM events WHERE job_id=? AND id>? ORDER BY id LIMIT 500",
                    (key, after),
                )
            ]

    def claim(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT id FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1"
            ).fetchone()
            if row is None:
                return None
            db.execute(
                "UPDATE jobs SET status='running',started_at=?,stage='worker_started' WHERE id=?",
                (now(), row["id"]),
            )
            key = row["id"]
        return self.job(key)

    def cancel(self, key):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            job = self.job_row(
                db.execute("SELECT * FROM jobs WHERE id=?", (key,)).fetchone()
            )
            if job["status"] not in TERMINAL:
                db.execute("UPDATE jobs SET cancel_requested=1 WHERE id=?", (key,))
                if job["status"] == "queued":
                    db.execute(
                        "UPDATE jobs SET status='cancelled',finished_at=? WHERE id=?",
                        (now(), key),
                    )
        return self.job(key)

    def finish(self, key, status, error=None, report_sha256=None, elapsed=None):
        if status not in TERMINAL:
            raise ValueError("invalid terminal state")
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT cancel_requested FROM jobs WHERE id=? AND status='running'",
                (key,),
            ).fetchone()
            if row is None:
                return
            if row[0] and status in {"completed", "completed_with_limitations"}:
                status, error, report_sha256 = (
                    "cancelled",
                    "Cancelled before atomic result publication",
                    None,
                )
            db.execute(
                "UPDATE jobs SET status=?,stage=?,finished_at=?,error=?,report_sha256=?,elapsed_seconds=? WHERE id=? AND status='running'",
                (status, status, now(), error, report_sha256, elapsed, key),
            )

    def recover(self):
        """Recover interrupted tasks, promoting only a verified final checkpoint.

        The scanner currently has one atomic report unit, not resumable shards.
        A report is recoverable only after the Worker has written its final
        manifest. Source-loaded/core-running outputs are never treated as done.
        """
        recovered = {"published": 0, "interrupted": 0, "cancelled": 0}
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("SELECT * FROM jobs WHERE status='running'").fetchall()
            for raw in rows:
                job = self.job_row(raw)
                stamp = now()
                if job["cancel_requested"]:
                    status, digest = "cancelled", None
                    error = "Cancellation was pending when Worker stopped; result was not published"
                    stage, event = "cancelled", "cancelled"
                    recovered["cancelled"] += 1
                else:
                    checkpoint = self._verified_artifact_checkpoint(job)
                    if checkpoint is not None:
                        status, digest = checkpoint
                        error = None
                        stage, event = "result_recovered", "result_recovered"
                        recovered["published"] += 1
                    else:
                        status, digest = "interrupted", None
                        error = (
                            "Worker stopped before a verified final report checkpoint; "
                            "incomplete analysis remains unknown and must be retried"
                        )
                        stage, event = "interrupted", "interrupted"
                        recovered["interrupted"] += 1
                db.execute(
                    "UPDATE jobs SET status=?,stage=?,finished_at=?,error=?,report_sha256=?,worker_pid=NULL "
                    "WHERE id=? AND status='running'",
                    (status, stage, stamp, error, digest, job["id"]),
                )
                message = (
                    "Recovered a fully verified atomic report checkpoint; no partial scan work was resumed"
                    if status in {"completed", "completed_with_limitations"}
                    else error
                )
                db.execute(
                    "INSERT INTO events(job_id,created_at,stage,message) VALUES(?,?,?,?)",
                    (job["id"], stamp, event, message[:4000]),
                )
        return recovered

    def _verified_artifact_checkpoint(self, job):
        """Return (report status, report digest) only for a complete bound manifest."""
        key = job["id"]
        if not isinstance(key, str) or re.fullmatch(r"[a-f0-9]{32}", key) is None:
            return None
        artifacts_root = self.root / "artifacts"
        job_dir = artifacts_root / key
        try:
            root_resolved = artifacts_root.resolve(strict=True)
            directory = job_dir.resolve(strict=True)
            if directory.parent != root_resolved or not directory.is_dir():
                return None
            manifest_path = directory / "manifest.json"
            report_path = directory / "report.json"
            markdown_path = directory / "report.md"
            if any(path.is_symlink() or not path.is_file() for path in
                   (manifest_path, report_path, markdown_path)):
                return None
            if (manifest_path.stat().st_size > 1024 * 1024
                    or report_path.stat().st_size > 64 * 1024 * 1024
                    or markdown_path.stat().st_size > 64 * 1024 * 1024):
                return None
            manifest = json.loads(manifest_path.read_bytes())
            report_bytes = report_path.read_bytes()
            markdown_bytes = markdown_path.read_bytes()
            report = json.loads(report_bytes)
        except (OSError, ValueError, UnicodeError, json.JSONDecodeError):
            return None
        report_hash = hashlib.sha256(report_bytes).hexdigest()
        markdown_hash = hashlib.sha256(markdown_bytes).hexdigest()
        if (not isinstance(manifest, dict) or manifest.get("schema_version") != 1
                or manifest.get("job_id") != key or manifest.get("spec") != job["spec"]):
            return None
        hashes = manifest.get("artifacts")
        if (not isinstance(hashes, dict) or hashes.get("report.json") != report_hash
                or hashes.get("report.md") != markdown_hash):
            return None
        status = report.get("status") if isinstance(report, dict) else None
        spec = job["spec"]
        if (status not in {"completed", "completed_with_limitations"}
                or report.get("commit") != spec.get("commit")
                or report.get("git_tree") != spec.get("git_tree")
                or report.get("repository") != spec.get("repository")):
            return None
        if spec.get("audit_plan") is not None and report.get("audit_plan") != spec.get("audit_plan"):
            return None
        return status, report_hash

    def add_review(self, job_id, candidate_id, status, reviewer, notes, expected_id):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT max(id) FROM reviews WHERE job_id=? AND candidate_id=?",
                (job_id, candidate_id),
            ).fetchone()
            if (row[0] or 0) != expected_id:
                raise ValueError("review changed; reload before saving")
            db.execute(
                "INSERT INTO reviews(job_id,candidate_id,status,reviewer,notes,created_at) VALUES(?,?,?,?,?,?)",
                (job_id, candidate_id, status, reviewer, notes, now()),
            )
        return self.reviews(job_id, candidate_id)

    def reviews(self, job_id, candidate_id=None):
        query = "SELECT * FROM reviews WHERE job_id=?"
        args = [job_id]
        if candidate_id is not None:
            query += " AND candidate_id=?"
            args.append(candidate_id)
        with self.connect() as db:
            return [dict(r) for r in db.execute(query + " ORDER BY id", args)]

    def create_case(self, title, links):
        key = uuid.uuid4().hex
        with self.connect() as db:
            db.execute("INSERT INTO cases VALUES(?,?,?)", (key, title, now()))
            for link in links:
                db.execute(
                    "INSERT INTO case_links VALUES(?,?,?,?)",
                    (key, link["job_id"], link["candidate_id"], link["rationale"]),
                )
        return key

    def cases(self):
        with self.connect() as db:
            result = []
            for row in db.execute("SELECT * FROM cases ORDER BY created_at DESC"):
                case = dict(row)
                case["status"] = "investigation"
                case["links"] = [
                    dict(x)
                    for x in db.execute(
                        "SELECT * FROM case_links WHERE case_id=?", (case["id"],)
                    )
                ]
                result.append(case)
            return result

    def add_source_evidence(self, job_id, candidate_id, record):
        key = uuid.uuid4().hex
        item = {
            "id": key,
            "job_id": job_id,
            "candidate_id": candidate_id,
            **record,
            "created_at": now(),
        }
        with self.connect() as db:
            db.execute(
                "INSERT INTO source_evidence VALUES(?,?,?,?,?)",
                (
                    key,
                    job_id,
                    candidate_id,
                    json.dumps(item, ensure_ascii=False),
                    item["created_at"],
                ),
            )
        return item

    def source_evidence(self, job_id, candidate_id=None):
        with self.connect() as db:
            if candidate_id is None:
                rows = db.execute(
                    "SELECT record FROM source_evidence WHERE job_id=? ORDER BY created_at,id",
                    (job_id,),
                )
            else:
                rows = db.execute(
                    "SELECT record FROM source_evidence WHERE job_id=? AND candidate_id=? ORDER BY created_at,id",
                    (job_id, candidate_id),
                )
            return [json.loads(row[0]) for row in rows]

    def link_case(self, case_id, links):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM cases WHERE id=?", (case_id,)).fetchone():
                raise KeyError("case not found")
            for link in links:
                db.execute(
                    "INSERT INTO case_links VALUES(?,?,?,?)",
                    (case_id, link["job_id"], link["candidate_id"], link["rationale"]),
                )
