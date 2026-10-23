"""Run on native Windows as well as Linux; no POSIX workbench dependencies."""
import subprocess
import sys
import time
import unittest
from unittest.mock import patch

from src.workbench.pipe_reader import PipeReader


class PipeReaderTests(unittest.TestCase):
    def test_progress_arrives_before_child_exits_without_newline(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import os,time; os.write(2, b'Receiving objects: 42% (42/100)\\r'); time.sleep(30)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        reader = PipeReader(process.stderr)
        try:
            self.assertEqual(reader.read(timeout=3), b"Receiving objects: 42% (42/100)\r")
            self.assertIsNone(process.poll())
        finally:
            process.terminate()
            process.wait(timeout=2)
            reader.close()
        self.assertFalse(reader.thread.is_alive())

    def test_real_pipe_large_output_and_eof_without_select(self):
        process = subprocess.Popen(
            [sys.executable, "-c", "import os; os.write(2, b'x' * 300000 + b'\\rfinal')"],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        reader = PipeReader(process.stderr)
        output = bytearray()
        try:
            with patch("selectors.DefaultSelector", side_effect=OSError(10038, "not a socket")):
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    chunk = reader.read()
                    if chunk is None:
                        break
                    output.extend(chunk)
                else:
                    self.fail("pipe drain timed out")
            self.assertEqual(process.wait(timeout=2), 0)
            self.assertEqual(output, b"x" * 300000 + b"\rfinal")
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=2)
            reader.close()
        self.assertTrue(process.stderr.closed)
        self.assertFalse(reader.thread.is_alive())

    def test_silent_pipe_does_not_block_monitor_and_closes_after_termination(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        reader = PipeReader(process.stderr)
        try:
            start = time.monotonic()
            self.assertEqual(reader.read(timeout=0.05), b"")
            self.assertLess(time.monotonic() - start, 2)
        finally:
            process.terminate()
            process.wait(timeout=2)
            reader.close()
        self.assertFalse(reader.thread.is_alive())
        self.assertTrue(process.stderr.closed)
