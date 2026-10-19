"""Incremental operation queue; old scan artifacts and identities stay untouched."""
import fcntl
import hashlib
import json
from pathlib import Path
import sqlite3
import statistics
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
    def directory(self, key):
        if len(key) != 32 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("invalid operation ID")
        return self.store.root / "operations" / key

    def create(self, kind, spec):
        if kind not in {"source_sync", "revision_range", "version_matrix", "branch_comparison", "validation", "investigation", "candidate_review_batch", "agent_investigation"}:
            raise ValueError("unknown operation kind")
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
            elif db.execute("SELECT count(*) FROM operations WHERE status IN ('queued','running') AND kind!='candidate_review_batch'").fetchone()[0] >= 100:
                raise ValueError("operation queue full")
            db.execute("INSERT INTO operations(id,kind,spec,status,created_at) VALUES(?,?,?,?,?)",
                       (key, kind, json.dumps(spec, sort_keys=True), "queued", now()))
        self.event(key, "queued", "Immutable operation plan saved")
        return self.get(key)

    def create_with_scans(self, kind, spec, repository_id, scan_specs):
        """Create an operation and its immutable endpoint jobs in one DB transaction."""
        if kind not in {"revision_range", "version_matrix", "branch_comparison"} or not scan_specs:
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
                "model_provider_configured": public_status()["configured"],
                "automatic_batch_processing_enabled": False,
                "limitations": ["Queue summary counts only static findings from completed reports.",
                                "Zero-candidate and partial/unanalyzed source coverage remain in scan reports and are not second-pass Agent reviews."]}

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
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.row(db.execute("SELECT * FROM operations WHERE id=?", (key,)).fetchone())
            if row["kind"] == "candidate_review_batch" and row["status"] not in END:
                raise ValueError("candidate review batches cannot be cancelled; all candidates must remain queued until review or explicit resolution")
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

    def record_agent_baseline_review(self, record):
        body = json.dumps(record, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        digest = hashlib.sha256(body.encode("utf-8")).hexdigest()
        stamp = now()
        with self.store.connect() as db:
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
        baseline_reviews = self.agent_baseline_reviews()
        baseline_by_candidate = {}
        for baseline in baseline_reviews:
            key = (baseline["experiment_id"], baseline["repository"], baseline["commit"], baseline["candidate_id"])
            baseline_by_candidate.setdefault(key, []).append(baseline)
        for task in self.list():
            if task["kind"] != "agent_investigation" or not task["result_sha256"]:
                continue
            reviews = self.agent_reviews(task["id"])
            if not reviews:
                continue
            result = self.result(task["id"])
            binding = result.get("binding") or {}
            experiment_id = task["spec"].get("experiment_id") or result.get("experiment_id")
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
            })
            group["operation_ids"].add(task["id"])
            candidate_key = (binding.get("repository"), binding.get("commit"),
                             binding.get("candidate_id", "unknown"))
            group["candidate_ids"].add(candidate_key)
            for review in reviews:
                group["reviews"].append(review)
                group["usefulness"][review["usefulness"]] += 1
                group["citation_accuracy"][review["citation_accuracy"]] += 1

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
            return {"review_count": len(items), "dispositions": dispositions,
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
        review = {
            **record,
            "operation_id": key,
            "result_sha256": task["result_sha256"],
            "binding": result.get("binding"),
            "model_assessment": result.get("agent_assessment", {}).get("assessment", "unknown"),
            "review_scope": "model_triage_quality_only",
        }
        encoded = json.dumps(review, ensure_ascii=False, sort_keys=True)
        if len(encoded.encode("utf-8")) > 3500:
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
