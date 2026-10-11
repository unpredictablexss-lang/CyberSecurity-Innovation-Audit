from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from research.experiments.cpp.shared_ptr_race_fixture_evidence import build, main


class SharedPtrRaceFixtureEvidenceTests(unittest.TestCase):
    def test_build_is_deterministic_and_write_check_roundtrip(self) -> None:
        first = build()
        second = build()
        self.assertEqual(first, second)
        payload = json.loads(first)
        self.assertEqual(len(payload["results"]), 1)
        result = payload["results"][0]
        self.assertEqual(result["tool"], "ohscanner.cpp.shared_ptr_race")
        self.assertEqual(result["tool_version"], "0.2.0-proposed")
        self.assertEqual(result["schema_version"], 1)
        self.assertEqual(result["status"], "blocked")

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "fixture_evidence.json"
            markdown = Path(directory) / "fixture_evidence.md"
            main(["--json-out", str(output), "--md-out", str(markdown)])
            self.assertTrue(markdown.read_text(encoding="utf-8").startswith(
                "# SharedPtrRace fixture evidence"
            ))
            main(
                [
                    "--json-out",
                    str(output),
                    "--md-out",
                    str(markdown),
                    "--check",
                ]
            )


if __name__ == "__main__":
    unittest.main()
