"""Pending research can never become an executable production rule."""
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from src.ohscanner.detectors.admission import pending_admissions
from src.ohscanner.detectors.catalog import build_registry, catalog_metadata, default_detector_ids
from src.ohscanner.planning import approved_metadata
from src.workbench.planning import plan_audit
from tests.test_audit_plan import manifest
from tests import test_workbench as wb
from src.workbench import service


class AdmissionBoundaryTests(unittest.TestCase):
    def test_selection_rejects_pending_without_instantiation(self):
        for row in pending_admissions():
            self.assertNotIn(row['id'], default_detector_ids())
            for ids in ((row['id'],), ('ohscanner.interface.ipc', row['id'])):
                with self.subTest(ids=ids), self.assertRaisesRegex(ValueError, 'admission blocked'):
                    build_registry(ids)

    def test_d_is_available_only_by_explicit_research_selection(self):
        ident = 'ohscanner.data.sensitive_exposure'
        self.assertNotIn(ident, default_detector_ids())
        metadata = catalog_metadata()[ident]
        self.assertEqual(metadata['kind'], 'research_candidate')
        self.assertFalse(metadata['default_enabled'])
        detector = build_registry((ident,)).detectors()[0]
        self.assertEqual(detector.version, '0.21.0')
        self.assertNotIn(ident, {row['id'] for row in pending_admissions()})
        automatic = plan_audit(manifest(), approved_metadata())
        automatic_row = next(row for row in automatic['detectors'] if row['id'] == ident)
        self.assertEqual(automatic_row['decision'], 'skipped')
        self.assertIn('explicit_selection_required', automatic_row['reason_codes'])
        explicit = plan_audit(manifest(), approved_metadata(), selected_detector_ids=[ident])
        explicit_row = next(row for row in explicit['detectors'] if row['id'] == ident)
        self.assertEqual(explicit_row['decision'], 'planned')
        self.assertIn(ident, explicit['suggested_detector_ids'])

    def test_complete_syntax_and_explicit_selection_do_not_bypass_review(self):
        for selected in (None, [row['id'] for row in pending_admissions()]):
            plan = plan_audit(manifest(), approved_metadata(), selected_detector_ids=selected)
            for row in pending_admissions():
                d = next(d for d in plan['detectors'] if d['id'] == row['id'])
                self.assertEqual(d['decision'], 'blocked')
                self.assertIn('admission_not_approved', d['reason_codes'])
                self.assertFalse(d['admission']['execution_enabled'])
                self.assertTrue(d['admission']['missing_evidence'])
                self.assertNotIn(row['id'], plan['suggested_detector_ids'])

    def test_candidate_metadata_cannot_change_the_default_selection_gate(self):
        ident = 'ohscanner.ark.runtime.type_safety'
        catalog_metadata()[ident]['default_enabled'] = True
        self.assertNotIn(ident, default_detector_ids())

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

    def test_static_c_candidate_is_not_reported_as_pending_admission(self):
        response = self.client.get('/api/v1/detector-admissions')
        self.assertEqual(response.status_code, 200)
        records = response.json()
        self.assertFalse(any(row['id'] == 'ohscanner.ark.runtime.type_safety' for row in records))

    def test_real_plan_explains_pending_without_running_them(self):
        before = self.client.get('/api/v1/scans').json()
        result = self.client.post('/api/v1/audit-plans', headers=wb.HEADERS,
            json={'repository_id': self.repo_id, 'revision': self.commit, 'include_paths': ['.']})
        self.assertEqual(result.status_code, 200, result.text)
        plan = result.json()
        pending = [d for d in plan['detectors'] if d.get('admission')]
        self.assertEqual(len(pending), 0)
        self.assertTrue(all(d['decision'] == 'blocked' for d in pending))
        self.assertEqual(self.client.get('/api/v1/scans').json(), before)
