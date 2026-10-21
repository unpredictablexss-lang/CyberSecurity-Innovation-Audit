"""Pending research can never become an executable production rule."""
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from src.ohscanner.detectors.admission import pending_admissions
from src.ohscanner.detectors.catalog import build_registry, catalog_metadata, default_detector_ids
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.planning import approved_metadata
from src.workbench.planning import plan_audit
from tests.test_audit_plan import manifest
from tests import test_workbench as wb
from src.workbench import service


class AdmissionBoundaryTests(unittest.TestCase):
    def test_c_is_an_explicit_only_approved_candidate(self):
        ident = "ohscanner.ark.runtime.type_safety"
        self.assertNotIn(ident, default_detector_ids())
        self.assertNotIn(ident, {row["id"] for row in pending_admissions()})
        metadata = catalog_metadata()[ident]
        self.assertEqual(metadata["kind"], "research_candidate")
        self.assertFalse(metadata["default_enabled"])
        detector = build_registry((ident,)).detectors()[0]
        self.assertEqual(detector.version, "0.6.3")
        automatic = plan_audit(manifest(), approved_metadata())
        automatic_row = next(row for row in automatic["detectors"] if row["id"] == ident)
        self.assertEqual(automatic_row["decision"], "skipped")
        self.assertIn("explicit_selection_required", automatic_row["reason_codes"])
        explicit = plan_audit(manifest(), approved_metadata(), selected_detector_ids=[ident])
        explicit_row = next(row for row in explicit["detectors"] if row["id"] == ident)
        self.assertEqual(explicit_row["decision"], "planned")
        self.assertIn(ident, explicit["suggested_detector_ids"])

    def test_d_is_available_only_by_explicit_research_selection(self):
        ident = 'ohscanner.data.sensitive_exposure'
        self.assertNotIn(ident, default_detector_ids())
        metadata = catalog_metadata()[ident]
        self.assertEqual(metadata['kind'], 'research_candidate')
        self.assertFalse(metadata['default_enabled'])
        detector = build_registry((ident,)).detectors()[0]
        self.assertEqual(detector.version, SensitiveExposureDetector.version)
        self.assertNotIn(ident, {row['id'] for row in pending_admissions()})
        automatic = plan_audit(manifest(), approved_metadata())
        automatic_row = next(row for row in automatic['detectors'] if row['id'] == ident)
        self.assertEqual(automatic_row['decision'], 'skipped')
        self.assertIn('explicit_selection_required', automatic_row['reason_codes'])
        explicit = plan_audit(manifest(), approved_metadata(), selected_detector_ids=[ident])
        explicit_row = next(row for row in explicit['detectors'] if row['id'] == ident)
        self.assertEqual(explicit_row['decision'], 'planned')
        self.assertIn(ident, explicit['suggested_detector_ids'])

    def test_model_bytes_frozen_and_missing_artifact_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            service_file = root / 'src/workbench/service.py'
            service_file.parent.mkdir(parents=True)
            model_path = 'src/ohscanner/detectors/reviewed-model.json'
            model = root / model_path
            model.parent.mkdir(parents=True)
            model.write_text('{"profile":"first"}')
            with patch.object(service, '__file__', str(service_file)), patch.object(service, 'ENGINE_MODEL_FILES', (model_path,)):
                before = service.engine_fingerprint()
                model.write_text('{"profile":"changed"}')
                self.assertNotEqual(before, service.engine_fingerprint())
                model.unlink()
                with self.assertRaises(FileNotFoundError):
                    service.engine_fingerprint()


@unittest.skipIf(wb.create_app is None, 'optional workbench dependencies unavailable')
class AdmissionApiTests(unittest.TestCase):
    setUp = wb.WorkbenchTests.setUp

    def test_pending_api_does_not_list_explicitly_admitted_c(self):
        c_id = "ohscanner.ark.runtime.type_safety"
        response = self.client.get("/api/v1/detector-admissions")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(c_id, {row["id"] for row in response.json()})
        before = self.client.get("/api/v1/scans").json()
        self.assertEqual(self.client.get("/api/v1/scans").json(), before)

    def test_real_plan_keeps_c_opt_in_without_running_it(self):
        c_id = "ohscanner.ark.runtime.type_safety"
        before = self.client.get("/api/v1/scans").json()
        result = self.client.post("/api/v1/audit-plans", headers=wb.HEADERS,
            json={"repository_id": self.repo_id, "revision": self.commit, "include_paths": ["."]})
        self.assertEqual(result.status_code, 200, result.text)
        plan = result.json()
        row = next(d for d in plan["detectors"] if d["id"] == c_id)
        self.assertFalse(row.get("admission"))
        self.assertEqual(row["decision"], "skipped")
        self.assertIn("explicit_selection_required", row["reason_codes"])
        self.assertEqual(self.client.get("/api/v1/scans").json(), before)
