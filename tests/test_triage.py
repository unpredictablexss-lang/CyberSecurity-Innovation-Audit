import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.core.scanner import scan_directory
from src.triage.callsite import parse_call_at_line
from src.triage.review import build_triage_report


REPO_ROOT = Path(__file__).resolve().parents[1]


class CandidateTriageTests(unittest.TestCase):
    def test_parse_simple_strcpy_arguments(self) -> None:
        lines = [
            "void demo(char *dst, const char *src)",
            "{",
            "    strcpy(dst, src);",
            "}",
        ]

        parsed = parse_call_at_line(lines, 3, "strcpy")

        self.assertEqual(parsed.status, "parsed_text_call")
        self.assertEqual(parsed.arguments, ["dst", "src"])
        self.assertEqual(parsed.start_line, 3)
        self.assertEqual(parsed.end_line, 3)

    def test_parse_nested_memcpy_arguments(self) -> None:
        lines = [
            "void demo(void)",
            "{",
            "    memcpy(get_dst(index + 1), get_src(a, b), size_fn(x, y));",
            "}",
        ]

        parsed = parse_call_at_line(lines, 3, "memcpy")

        self.assertEqual(parsed.status, "parsed_text_call")
        self.assertEqual(
            parsed.arguments,
            ["get_dst(index + 1)", "get_src(a, b)", "size_fn(x, y)"],
        )

    def test_parse_multiline_sprintf_and_string_comma(self) -> None:
        lines = [
            "void demo(char *dst, int value)",
            "{",
            "    sprintf(dst,",
            '            "value,%d",',
            "            value);",
            "}",
        ]

        parsed = parse_call_at_line(lines, 3, "sprintf")

        self.assertEqual(parsed.status, "parsed_text_call")
        self.assertEqual(parsed.start_line, 3)
        self.assertEqual(parsed.end_line, 5)
        self.assertEqual(parsed.arguments[0], "dst")
        self.assertEqual(parsed.arguments[1], '"value,%d"')
        self.assertEqual(parsed.arguments[2], "value")

    def test_build_triage_report_adds_obligations_without_promoting_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.c"
            source.write_text(
                "void demo(char *dst, const char *src, int n)\n"
                "{\n"
                "    memcpy(dst, src, n);\n"
                "}\n",
                encoding="utf-8",
            )

            scan_result = scan_directory(root)
            scan_report = root / "scan.json"
            scan_report.write_text(
                json.dumps(scan_result.to_dict(), indent=2),
                encoding="utf-8",
            )

            triage = build_triage_report(scan_report)

        self.assertEqual(triage.candidate_count, 1)
        self.assertEqual(triage.packet_count, 1)
        packet = triage.packets[0]
        self.assertEqual(packet.call_name, "memcpy")
        self.assertEqual(packet.call_arguments, ["dst", "src", "n"])
        self.assertEqual(packet.review.review_status, "unreviewed")
        self.assertEqual(packet.review.runtime_validation, "not_started")
        self.assertTrue(packet.obligations)
        self.assertEqual(len(packet.candidate_id), 16)

    def test_cli_triage_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            target = temp / "target"
            target.mkdir()
            source = target / "demo.c"
            source.write_text(
                "void demo(char *dst, const char *src)\n"
                "{\n"
                "    strcpy(dst, src);\n"
                "}\n",
                encoding="utf-8",
            )

            scan_result = scan_directory(target)
            scan_report = temp / "scan.json"
            scan_report.write_text(
                json.dumps(scan_result.to_dict(), indent=2),
                encoding="utf-8",
            )

            json_output = temp / "triage.json"
            md_output = temp / "triage.md"
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "src.cli",
                    "triage",
                    "--scan-report",
                    str(scan_report),
                    "--json-out",
                    str(json_output),
                    "--md-out",
                    str(md_output),
                ],
                cwd=REPO_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(process.returncode, 0, process.stderr)
            data = json.loads(json_output.read_text(encoding="utf-8"))
            markdown = md_output.read_text(encoding="utf-8")

        self.assertEqual(data["candidate_count"], 1)
        self.assertEqual(data["packet_count"], 1)
        packet = data["packets"][0]
        self.assertEqual(packet["call_name"], "strcpy")
        self.assertEqual(packet["call_arguments"], ["dst", "src"])
        self.assertEqual(packet["review"]["review_status"], "unreviewed")
        self.assertIn("Structured review aid only", markdown)
        self.assertIn("Security obligations to review", markdown)
        self.assertIn("[OK] candidate packets: 1", process.stdout)
        self.assertIn("[OK] parsed call expressions: 1", process.stdout)


if __name__ == "__main__":
    unittest.main()
