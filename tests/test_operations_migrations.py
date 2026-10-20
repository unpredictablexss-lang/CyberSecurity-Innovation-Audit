"""Concurrent operations schema migrations remain serialized and recoverable."""
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from src.workbench.operations_store import Operations
from src.workbench.store import Store


class OperationsMigrationConcurrencyTests(unittest.TestCase):
    def test_parallel_v7_to_v9_migrations_are_serialized(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = root / "data"
            store = Store(data)
            Operations(store)
            with store.connect() as db:
                for column in (
                    "r2_error", "r2_decision_sha256", "r2_candidate_manifest",
                    "r2_operation_ids", "r2_status",
                ):
                    db.execute("ALTER TABLE smart_triage_batches DROP COLUMN " + column)
                db.execute("DROP TABLE triage_cancellations")
                db.execute("DELETE FROM schema_migrations WHERE version>=8")
                version = db.execute(
                    "SELECT max(version) FROM schema_migrations").fetchone()[0]
            self.assertEqual(version, 7)

            gate = root / "start-migration"
            child = (
                "import sys, time\n"
                "from pathlib import Path\n"
                "from src.workbench.operations_store import Operations\n"
                "from src.workbench.store import Store\n"
                "data, gate = Path(sys.argv[1]), Path(sys.argv[2])\n"
                "while not gate.exists(): time.sleep(0.005)\n"
                "Operations(Store(data))\n"
            )
            environment = dict(os.environ)
            project = str(Path(__file__).resolve().parents[1])
            environment["PYTHONPATH"] = os.pathsep.join(
                item for item in (project, environment.get("PYTHONPATH", "")) if item)
            processes = [
                subprocess.Popen(
                    [sys.executable, "-c", child, str(data), str(gate)],
                    cwd=project, env=environment, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                )
                for _ in range(4)
            ]
            gate.touch()
            outputs = []
            try:
                for process in processes:
                    output, _ = process.communicate(timeout=20)
                    outputs.append((process.returncode, output))
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                        process.wait()
            self.assertTrue(all(code == 0 for code, _ in outputs), repr(outputs))
            with sqlite3.connect(store.path) as db:
                self.assertEqual(db.execute(
                    "SELECT max(version) FROM schema_migrations").fetchone()[0], 9)
                cancellation_columns = {row[1] for row in db.execute(
                    "PRAGMA table_info(triage_cancellations)")}
                columns = {row[1] for row in db.execute(
                    "PRAGMA table_info(smart_triage_batches)")}
            self.assertTrue({
                "r2_status", "r2_operation_ids", "r2_candidate_manifest",
                "r2_decision_sha256", "r2_error",
            }.issubset(columns))
            self.assertTrue({"audit_id", "report_sha256", "created_at"}.issubset(cancellation_columns))


if __name__ == "__main__":
    unittest.main()
