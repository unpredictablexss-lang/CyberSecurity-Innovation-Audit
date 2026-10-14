import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pydantic import ValidationError

from src.workbench.api import ScanInput
from src.workbench.service import MAX_INCLUDE_PATHS, make_spec


class WorkbenchScopeLimitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo_path = self.root / "repo"
        self.repo_path.mkdir()
        self.repo = {
            "name": "openharmony/fixture",
            "path": str(self.repo_path),
        }

    def spec(self, count):
        with patch(
            "src.workbench.service.revision",
            return_value={
                "requested_revision": "HEAD",
                "commit": "a" * 40,
                "git_tree": "b" * 40,
            },
        ):
            return make_spec(
                self.repo,
                "HEAD",
                [f"path/{index}.cpp" for index in range(count)],
                ("ohscanner.cpp.shared_ptr_race",),
                300,
                2048,
            )

    def test_make_spec_accepts_one_hundred_and_two_thousand_paths(self):
        self.assertEqual(len(self.spec(1)["include_paths"]), 1)
        self.assertEqual(len(self.spec(100)["include_paths"]), 100)
        self.assertEqual(len(self.spec(MAX_INCLUDE_PATHS)["include_paths"]), 2000)

    def test_scan_input_accepts_exact_manifest_sized_path_list(self):
        body = ScanInput(
            repository_id="repo",
            revision="HEAD",
            include_paths=[f"path/{index}.cpp" for index in range(MAX_INCLUDE_PATHS)],
            detector_ids=["ohscanner.cpp.shared_ptr_race"],
        )
        self.assertEqual(len(body.include_paths), MAX_INCLUDE_PATHS)

    def test_scan_input_rejects_more_than_two_thousand_paths(self):
        with self.assertRaises(ValidationError):
            ScanInput(
                repository_id="repo",
                revision="HEAD",
                include_paths=[
                    f"path/{index}.cpp" for index in range(MAX_INCLUDE_PATHS + 1)
                ],
                detector_ids=["ohscanner.cpp.shared_ptr_race"],
            )

    def test_make_spec_rejects_duplicate_paths(self):
        with self.assertRaisesRegex(ValueError, "distinct"):
            make_spec(
                self.repo,
                "HEAD",
                ["same.cpp", "same.cpp"],
                ("ohscanner.cpp.shared_ptr_race",),
                300,
                2048,
            )

    def test_make_spec_rejects_path_traversal(self):
        with self.assertRaises(ValueError):
            make_spec(
                self.repo,
                "HEAD",
                ["../outside.cpp"],
                ("ohscanner.cpp.shared_ptr_race",),
                300,
                2048,
            )


if __name__ == "__main__":
    unittest.main()
