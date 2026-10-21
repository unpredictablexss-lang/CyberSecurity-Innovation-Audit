import subprocess
import tempfile
import unittest
from pathlib import Path

from src.ohscanner.execution import run_fixed_commit_scan


class IncrementalFallbackEquivalenceTests(unittest.TestCase):
    def test_incremental_request_falls_back_and_preserves_full_head_result(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = Path(directory) / "repo"
            repo.mkdir()
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.email", "test@example.invalid"], check=True)
            subprocess.run(["git", "-C", str(repo), "config", "user.name", "Test"], check=True)
            (repo / "source.cpp").write_text("void f(){ use(); use(); }\n")
            subprocess.run(["git", "-C", str(repo), "add", "source.cpp"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "base"], check=True)
            base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            (repo / "source.cpp").write_text("void f(){ use(); use(); use(); }\n")
            (repo / "partial.cpp").write_text("void broken( {\n")
            subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
            subprocess.run(["git", "-C", str(repo), "commit", "-qm", "head"], check=True)
            head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()

            def scan(output_dir, incremental):
                return run_fixed_commit_scan(
                    repo, "fixture/incremental", head, (".",),
                    ("ohscanner.example.cpp.copy-calls",),
                    output_dir / "report.json", output_dir / "report.md",
                    allow_examples=True, base_commit=base if incremental else None)

            normal = scan(Path(directory) / "normal", False)
            requested = scan(Path(directory) / "incremental", True)
            for key in ("commit", "git_tree", "status", "diagnostic_count", "source_parsing",
                        "detector_coverage", "files_in_scope_without_a_claiming_detector"):
                self.assertEqual(normal[key], requested[key], key)
            normal_findings = normal["detector_runs"][0]["diagnostics"]
            requested_findings = requested["detector_runs"][0]["diagnostics"]
            identity = lambda rows: sorted((row["diagnostic_id"], row["file"], row["line"], row["column"])
                                           for row in rows)
            self.assertEqual(identity(normal_findings), identity(requested_findings))
            self.assertEqual(requested["incremental"]["execution"], "full_scan_required")
            self.assertEqual(requested["incremental"]["reused_files"], 0)
            self.assertEqual(requested["source_parsing"], normal["source_parsing"])


if __name__ == "__main__":
    unittest.main()
