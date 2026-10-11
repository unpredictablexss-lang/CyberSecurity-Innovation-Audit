"""Transactional single-machine queue and append-only review history."""
from contextlib import contextmanager
from datetime import datetime, timezone
import json
from pathlib import Path
import sqlite3
import uuid

TERMINAL = {"completed", "completed_with_limitations", "failed", "cancelled", "interrupted", "timed_out"}

def now():
    return datetime.now(timezone.utc).isoformat()

class Store:
    def __init__(self, data_dir: Path):
        self.root = data_dir
        data_dir.mkdir(parents=True, exist_ok=True)
        self.path = data_dir / "workbench.sqlite3"
        with self.connect() as db:
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
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=15)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
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
            return [dict(r) for r in db.execute("SELECT * FROM repositories ORDER BY created_at")]

    def repository(self, key):
        with self.connect() as db:
            row = db.execute("SELECT * FROM repositories WHERE id=?", (key,)).fetchone()
            if row is None:
                raise KeyError("repository not found")
            return dict(row)

    def add_repository(self, name, path):
        key = uuid.uuid4().hex
        with self.connect() as db:
            db.execute("INSERT INTO repositories VALUES(?,?,?,?)", (key,name,str(path),now()))
        return self.repository(key)

    def create_job(self, repository_id, spec):
        key = uuid.uuid4().hex
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT count(*) FROM jobs WHERE status IN ('queued','running')").fetchone()[0] >= 100:
                raise ValueError("queue capacity reached")
            db.execute("INSERT INTO jobs(id,repository_id,spec,status,stage,created_at) VALUES(?,?,?,?,?,?)",
                       (key, repository_id, json.dumps(spec,sort_keys=True), "queued","source_pinned",now()))
            db.execute("INSERT INTO events(job_id,created_at,stage,message) VALUES(?,?,?,?)",
                       (key,now(),"source_pinned","Requested revision resolved to immutable commit/tree"))
        return self.job(key)

    def job(self, key):
        with self.connect() as db:
            return self.job_row(db.execute("SELECT * FROM jobs WHERE id=?", (key,)).fetchone())

    def jobs(self):
        with self.connect() as db:
            return [self.job_row(r) for r in db.execute("SELECT * FROM jobs ORDER BY created_at DESC LIMIT 200")]

    def event(self, key, stage, message):
        with self.connect() as db:
            db.execute("UPDATE jobs SET stage=? WHERE id=?", (stage,key))
            db.execute("INSERT INTO events(job_id,created_at,stage,message) VALUES(?,?,?,?)",
                       (key,now(),stage,message[:4000]))

    def events(self, key, after=0):
        self.job(key)
        with self.connect() as db:
            return [dict(r) for r in db.execute(
                "SELECT * FROM events WHERE job_id=? AND id>? ORDER BY id LIMIT 500", (key,after))]

    def claim(self):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT id FROM jobs WHERE status='queued' ORDER BY created_at LIMIT 1").fetchone()
            if row is None:
                return None
            db.execute("UPDATE jobs SET status='running',started_at=?,stage='worker_started' WHERE id=?",
                       (now(),row["id"]))
            key = row["id"]
        return self.job(key)

    def cancel(self, key):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            job = self.job_row(db.execute("SELECT * FROM jobs WHERE id=?", (key,)).fetchone())
            if job["status"] not in TERMINAL:
                db.execute("UPDATE jobs SET cancel_requested=1 WHERE id=?", (key,))
                if job["status"] == "queued":
                    db.execute("UPDATE jobs SET status='cancelled',finished_at=? WHERE id=?", (now(),key))
        return self.job(key)

    def finish(self, key, status, error=None, report_sha256=None, elapsed=None):
        if status not in TERMINAL:
            raise ValueError("invalid terminal state")
        with self.connect() as db:
            db.execute("UPDATE jobs SET status=?,stage=?,finished_at=?,error=?,report_sha256=?,elapsed_seconds=? WHERE id=? AND status='running'",
                       (status,status,now(),error,report_sha256,elapsed,key))

    def recover(self):
        # Only call after acquiring the exclusive Worker lock.
        with self.connect() as db:
            db.execute("UPDATE jobs SET status='interrupted',stage='interrupted',finished_at=?,error=? WHERE status='running'",
                       (now(),"Worker stopped before committing a complete result; retry explicitly"))

    def add_review(self, job_id, candidate_id, status, reviewer, notes, expected_id):
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT max(id) FROM reviews WHERE job_id=? AND candidate_id=?",
                             (job_id,candidate_id)).fetchone()
            if (row[0] or 0) != expected_id:
                raise ValueError("review changed; reload before saving")
            db.execute("INSERT INTO reviews(job_id,candidate_id,status,reviewer,notes,created_at) VALUES(?,?,?,?,?,?)",
                       (job_id,candidate_id,status,reviewer,notes,now()))
        return self.reviews(job_id,candidate_id)

    def reviews(self, job_id, candidate_id=None):
        query = "SELECT * FROM reviews WHERE job_id=?"
        args = [job_id]
        if candidate_id is not None:
            query += " AND candidate_id=?"
            args.append(candidate_id)
        with self.connect() as db:
            return [dict(r) for r in db.execute(query+" ORDER BY id",args)]

    def create_case(self, title, links):
        key = uuid.uuid4().hex
        with self.connect() as db:
            db.execute("INSERT INTO cases VALUES(?,?,?)", (key,title,now()))
            for link in links:
                db.execute("INSERT INTO case_links VALUES(?,?,?,?)",
                           (key,link["job_id"],link["candidate_id"],link["rationale"]))
        return key

    def cases(self):
        with self.connect() as db:
            result = []
            for row in db.execute("SELECT * FROM cases ORDER BY created_at DESC"):
                case = dict(row)
                case["status"] = "investigation"
                case["links"] = [dict(x) for x in db.execute("SELECT * FROM case_links WHERE case_id=?", (case["id"],))]
                result.append(case)
            return result
