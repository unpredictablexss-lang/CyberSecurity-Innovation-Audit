from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.check_docs_context_budget import (
    ARCHIVE_DOCUMENT,
    ARCHIVE_MANIFEST,
    BASE_CONTEXT_BUDGET,
    CHARACTER_BUDGETS,
    DOC_NAMES,
    REQUIRED_HEADINGS,
    collect_problems,
    count_characters,
)


class DocsContextBudgetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "docs").mkdir()
        (self.root / ARCHIVE_DOCUMENT.parent).mkdir(parents=True, exist_ok=True)

    def write_context_files(self, replacements: dict[str, str] | None = None) -> None:
        replacements = replacements or {}
        for relative, headings in REQUIRED_HEADINGS.items():
            text = replacements.get(relative, "\n".join(headings) + "\n")
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8", newline="\n")

        archive = self.root / ARCHIVE_DOCUMENT
        archive.write_text("历史归档\n", encoding="utf-8", newline="\n")
        archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
        manifest = {
            "schema": "ohscanner.status-archive.v1",
            "source_path": "docs/项目现状与下一步.md",
            "archive_path": ARCHIVE_DOCUMENT.as_posix(),
            "source_sha256": archive_hash,
            "archive_sha256": archive_hash,
            "repository_head": "a" * 40,
            "migrated_at": "2026-10-16T00:00:00+08:00",
        }
        (self.root / ARCHIVE_MANIFEST).write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
            newline="\n",
        )

    def test_repository_guides_satisfy_current_budgets(self) -> None:
        repository_root = Path(__file__).resolve().parents[1]
        self.assertEqual(collect_problems(repository_root), [])

    def test_minimal_utf8_fixture_passes(self) -> None:
        self.write_context_files({"docs/README.md": "# OHScanner：新 Agent 从这里开始\n\n## 何时读取\n\n## 项目边界\n"})
        self.assertEqual(collect_problems(self.root), [])

    def test_extra_markdown_is_rejected(self) -> None:
        self.write_context_files()
        (self.root / "docs" / "extra.md").write_text("# extra\n", encoding="utf-8")
        self.assertIn("unexpected Markdown in docs/: extra.md", collect_problems(self.root))

    def test_nested_extra_markdown_is_rejected(self) -> None:
        self.write_context_files()
        nested = self.root / "docs" / "history"
        nested.mkdir()
        (nested / "extra.md").write_text("# extra\n", encoding="utf-8")
        self.assertIn(
            "unexpected Markdown in docs/: history/extra.md",
            collect_problems(self.root),
        )

    def test_missing_required_heading_is_rejected(self) -> None:
        self.write_context_files({"docs/README.md": "# OHScanner：新 Agent 从这里开始\n"})
        self.assertIn(
            "docs/README.md is missing required heading: ## 何时读取",
            collect_problems(self.root),
        )

    def test_character_budget_is_enforced(self) -> None:
        budget = CHARACTER_BUDGETS["docs/README.md"]
        self.write_context_files(
            {"docs/README.md": "\n".join(REQUIRED_HEADINGS["docs/README.md"]) + "\n" + "x" * budget}
        )
        self.assertTrue(
            any("docs/README.md has" in problem for problem in collect_problems(self.root))
        )

    def test_default_context_budget_is_enforced(self) -> None:
        padding = "x" * BASE_CONTEXT_BUDGET
        replacements = {
            "AGENTS.md": "\n".join(REQUIRED_HEADINGS["AGENTS.md"]) + "\n" + padding,
            "docs/项目现状与下一步.md": "\n".join(
                REQUIRED_HEADINGS["docs/项目现状与下一步.md"]
            )
            + "\n",
        }
        self.write_context_files(replacements)
        self.assertTrue(
            any("default context pack has" in problem for problem in collect_problems(self.root))
        )

    def test_archive_hash_mismatch_is_rejected(self) -> None:
        self.write_context_files()
        manifest_path = self.root / ARCHIVE_MANIFEST
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["archive_sha256"] = "0" * 64
        manifest["source_sha256"] = "0" * 64
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        self.assertIn(
            "status archive bytes do not match archive_sha256",
            collect_problems(self.root),
        )

    def test_lf_and_crlf_have_equal_character_counts(self) -> None:
        lf = self.root / "lf.md"
        crlf = self.root / "crlf.md"
        text = "# 标题\n\n中文内容\n"
        lf.write_bytes(text.encode("utf-8"))
        crlf.write_bytes(text.replace("\n", "\r\n").encode("utf-8"))
        self.assertEqual(count_characters(lf), count_characters(crlf))

    def test_empty_file_fails_required_headings_but_not_length_budget(self) -> None:
        self.write_context_files({"docs/README.md": ""})
        problems = collect_problems(self.root)
        self.assertFalse(any("docs/README.md has" in problem for problem in problems))
        self.assertTrue(any("missing required heading" in problem for problem in problems))


if __name__ == "__main__":
    unittest.main()
