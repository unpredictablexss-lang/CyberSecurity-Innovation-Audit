"""Owner-side Catalog and API/Worker admission checks for the A candidate."""
import unittest

from src.ohscanner.detectors.catalog import (
    build_registry, catalog_metadata, default_detector_ids,
)
from src.ohscanner.planning import approved_metadata
from src.ohscanner.execution import run_fixed_commit_scan
from src.workbench.planning import plan_audit
from tests.test_audit_plan import manifest
from tests import test_workbench as fixtures
from src.workbench.worker import Worker
from src.workbench import service


IDENT = "ohscanner.cpp.path_traversal"
RULE = "ohcpp-path-traversal-source-to-file-sink-candidate-001"


class ContactsCatalogAdmissionTests(unittest.TestCase):
    def test_registered_opt_in_detector_and_explicit_planning(self):
        metadata = catalog_metadata()[IDENT]
        self.assertEqual(metadata["kind"], "research_candidate")
        self.assertFalse(metadata["default_enabled"])
        self.assertIn("explicit_selection_required", metadata["admission_reason"])
        self.assertNotIn(IDENT, default_detector_ids())
        self.assertEqual(build_registry((IDENT,)).detectors()[0].version, "0.3.0")

        automatic = plan_audit(manifest(), approved_metadata())
        row = next(item for item in automatic["detectors"] if item["id"] == IDENT)
        self.assertEqual(row["decision"], "skipped")
        self.assertIn("explicit_selection_required", row["reason_codes"])

        explicit = plan_audit(manifest(), approved_metadata(), selected_detector_ids=[IDENT])
        row = next(item for item in explicit["detectors"] if item["id"] == IDENT)
        self.assertEqual(row["decision"], "planned")
        self.assertEqual(explicit["suggested_detector_ids"], [IDENT])


@unittest.skipIf(fixtures.create_app is None, "optional workbench dependencies unavailable")
class ContactsCatalogApiWorkerTests(unittest.TestCase):
    setUp = fixtures.WorkbenchTests.setUp

    def test_metadata_preview_and_explicit_scan_worker_path(self):
        metadata = self.client.get("/api/v1/detectors")
        self.assertEqual(metadata.status_code, 200)
        row = next(item for item in metadata.json() if item["id"] == IDENT)
        self.assertFalse(row["default_enabled"])

        source = r'''
struct Bucket { Value Get(const std::string &key) const; };
std::string ReadTextField(const Bucket &bucket, const std::string &key) {
  Value valueObject = bucket.Get(key);
  std::string value;
  if (const auto *stringPtr = std::get_if<std::string>(&valueObject.value)) value = *stringPtr;
  return value;
}
void Handle(const Bucket &bucket) {
  std::string filename = ReadTextField(bucket, "input");
  std::string path = GetStorageRoot() + filename;
  open(path.c_str(), O_RDONLY);
}
'''
        path = self.repo / "contacts.cpp"
        path.write_text(source)
        fixtures.git(self.repo, "add", "contacts.cpp")
        fixtures.git(self.repo, "commit", "-qm", "Contacts path flow fixture")
        self.commit = fixtures.git(self.repo, "rev-parse", "HEAD")
        request = {"repository_id": self.repo_id, "revision": self.commit,
                   "include_paths": ["."], "detector_ids": [IDENT]}
        preview = self.client.post("/api/v1/audit-plans", headers=fixtures.HEADERS,
                                   json=request)
        self.assertEqual(preview.status_code, 200, preview.text)
        plan = preview.json()
        self.assertEqual(plan["suggested_detector_ids"], [IDENT])
        self.assertEqual(plan["selection_mode"], "explicit")
        queued = self.client.post("/api/v1/scans", headers=fixtures.HEADERS,
            json={**request, "expected_plan_sha256": plan["plan_sha256"]})
        self.assertEqual(queued.status_code, 201, queued.text)
        job = queued.json()
        Worker(self.settings).run(once=True)
        finished = self.store.job(job["id"])
        report = service.read_report(self.settings, finished)
        run = next(item for item in report["detector_runs"] if item["tool"] == IDENT)
        self.assertTrue(any(item["rule_id"] == RULE for item in run["diagnostics"]))
        self.assertEqual(run["tool_version"], "0.3.0")
        self.assertEqual(report["validated_vulnerability"], 0)

        cli_report = run_fixed_commit_scan(
            self.repo, "fixture/contacts", self.commit, (".",), (IDENT,),
            self.root / "contacts-cli.json", self.root / "contacts-cli.md",
        )
        cli_run = next(item for item in cli_report["detector_runs"] if item["tool"] == IDENT)
        self.assertEqual(
            [(item["file"], item["line"], item["rule_id"]) for item in cli_run["diagnostics"]],
            [(item["file"], item["line"], item["rule_id"]) for item in run["diagnostics"]],
        )
        self.assertEqual(cli_run["tool_version"], run["tool_version"])


if __name__ == "__main__":
    unittest.main()
