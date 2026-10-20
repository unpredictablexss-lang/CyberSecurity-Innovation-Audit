import tempfile
from pathlib import Path
import unittest

from scripts.local_workspace import workspace_path


class WorkspacePathTests(unittest.TestCase):
    def test_relative_paths_resolve_from_workspace_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.assertEqual(workspace_path("app", root), (root / "app").resolve())

    def test_home_paths_expand_independently_of_workspace(self):
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(workspace_path("~/targets", Path(directory)), Path.home() / "targets")

    def test_empty_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "non-empty"):
                workspace_path(" ", Path(directory))


if __name__ == "__main__":
    unittest.main()
