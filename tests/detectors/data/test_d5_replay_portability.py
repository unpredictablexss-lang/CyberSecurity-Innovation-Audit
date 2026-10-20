"""Offline replays must preserve blocked output and budgets on Windows too."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("d5_portable_replay", ROOT / "research/data_sensitive/d5_replay.py")
replay = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(replay)


class ReplayPortabilityTests(unittest.TestCase):
    def test_unavailable_resource_measurement_is_unknown(self):
        with patch.object(replay, "resource", None):
            self.assertIsNone(replay.peak_rss())

    def test_wall_budget_kills_child_and_records_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "blocked.json"
            result = replay.bounded_child(
                [sys.executable, "-c", "import time; time.sleep(10)"], output, 0.1)
            self.assertEqual(result, 2)
            record = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(record["status"], "blocked")
            self.assertEqual(record["error_type"], "TimeoutError")
            self.assertEqual(record["network_access"], "not attempted")

    def test_child_exit_code_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "result.json"
            result = replay.bounded_child([sys.executable, "-c", "raise SystemExit(7)"], output, 5)
            self.assertEqual(result, 7)
            self.assertFalse(output.exists())
