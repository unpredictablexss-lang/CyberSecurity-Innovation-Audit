from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient

from src.workbench.api import create_app
from src.workbench.settings import Settings


class ServedUiTests(unittest.TestCase):
    def test_built_frontend_and_assets_are_served(self):
        with tempfile.TemporaryDirectory() as directory:
            settings = Settings(Path(directory) / "data", (Path(directory) / "targets",))
            client = TestClient(create_app(settings))
            self.addCleanup(client.close)

            page = client.get("/")
            self.assertEqual(page.status_code, 200, page.text)
            self.assertIn('id="root"', page.text)
            self.assertIn("/assets/app.js", page.text)

            for asset in ("/assets/app.js", "/assets/app.css"):
                response = client.get(asset)
                self.assertEqual(response.status_code, 200, response.text)
                self.assertGreater(len(response.content), 0)


if __name__ == "__main__":
    unittest.main()
