import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

from src.baseline.clang_analyzer import (
    parse_clang_diagnostics,
    run_clang_analyzer,
)


REPO_ROOT = Path(__file__).resolve().parents[1]


class ClangAnalyzerBaselineTests(unittest.TestCase):
    def test_parse_clang_diagnostics_extracts_checker(self) -> None:
        text = (
            "/tmp/demo.c:12:7: warning: Call to function 'strcpy' is insecure "
            "[security.insecureAPI.strcpy]\n"
            "/tmp/demo.c:13:3: note: expanded from macro 'COPY'\n"
        )

        diagnostics = parse_clang_diagnostics(text)

        self.assertEqual(len(diagnostics), 2)
        warning = diagnostics[0]
        self.assertEqual(warning.file, "/tmp/demo.c")
        self.assertEqual(warning.line, 12)
        self.assertEqual(warning.column, 7)
        self.assertEqual(warning.level, "warning")
        self.assertEqual(warning.checker, "security.insecureAPI.strcpy")
        self.assertNotIn("[security.insecureAPI.strcpy]", warning.message)

    def test_runner_rejects_source_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.c").write_text("int main(void){return 0;}\n", encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "escapes target root"):
                run_clang_analyzer(
                    root,
                    files=["../outside.c"],
                    clang_executable=sys.executable,
                )

    def test_runner_collects_fake_clang_diagnostics(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "demo.c"
            source.write_text("void demo(void) {}\n", encoding="utf-8")

            fake_clang = root / "fake-clang"
            fake_clang.write_text(
                textwrap.dedent(
                    """                    #!/usr/bin/env python3
                    import pathlib
                    import sys

                    if "--version" in sys.argv:
                        print("Fake clang version 1.0")
                        raise SystemExit(0)

                    source = pathlib.Path(sys.argv[-1])
                    print(
                        f"{source}:1:1: warning: synthetic baseline warning "
                        "[debug.synthetic]",
                        file=sys.stderr,
                    )
                    raise SystemExit(0)
                    """
                ),
                encoding="utf-8",
            )
            fake_clang.chmod(fake_clang.stat().st_mode | 0o111)

            result = run_clang_analyzer(
                root,
                files=["demo.c"],
                clang_executable=str(fake_clang),
            )

        self.assertEqual(result.clang_version, "Fake clang version 1.0")
        self.assertEqual(result.files, ["demo.c"])
        self.assertEqual(result.failed_files, [])
        self.assertEqual(result.diagnostic_count, 1)
        self.assertEqual(result.diagnostics[0].file, "demo.c")
        self.assertEqual(result.diagnostics[0].checker, "debug.synthetic")
        self.assertEqual(result.file_results[0].exit_code, 0)

    def test_cli_baseline_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            target = temp / "target"
            target.mkdir()
            source = target / "demo.c"
            source.write_text("void demo(void) {}\n", encoding="utf-8")

            fake_clang = temp / "fake-clang"
            fake_clang.write_text(
                textwrap.dedent(
                    """                    #!/usr/bin/env python3
                    import pathlib
                    import sys

                    if "--version" in sys.argv:
                        print("Fake clang version 2.0")
                        raise SystemExit(0)

                    source = pathlib.Path(sys.argv[-1])
                    print(
                        f"{source}:1:2: warning: cli synthetic warning "
                        "[debug.cli]",
                        file=sys.stderr,
                    )
                    raise SystemExit(0)
                    """
                ),
                encoding="utf-8",
            )
            fake_clang.chmod(fake_clang.stat().st_mode | 0o111)

            json_output = temp / "baseline.json"
            md_output = temp / "baseline.md"
            process = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "src.cli",
                    "baseline-clang",
                    str(target),
                    "--file",
                    "demo.c",
                    "--clang",
                    str(fake_clang),
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

        self.assertEqual(data["tool"], "clang-static-analyzer")
        self.assertEqual(data["file_count"], 1)
        self.assertEqual(data["diagnostic_count"], 1)
        self.assertEqual(data["diagnostics"][0]["checker"], "debug.cli")
        self.assertIn("Baseline diagnostics only", markdown)
        self.assertIn("debug.cli", markdown)
        self.assertIn("[OK] diagnostics: 1", process.stdout)


if __name__ == "__main__":
    unittest.main()
