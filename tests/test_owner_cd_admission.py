"""Pending research can never become an executable production rule."""
import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch
from src.ohscanner.detectors.admission import pending_admissions
from src.ohscanner.detectors.catalog import build_registry, default_detector_ids
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

    def test_returned_records_cannot_change_the_gate(self):
        row = pending_admissions()[0]
        row['missing_evidence'].clear()
        row['execution_enabled'] = True
        self.assertTrue(pending_admissions()[0]['missing_evidence'])
        self.assertFalse(pending_admissions()[0]['execution_enabled'])

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

    def test_readable_but_cannot_enqueue_or_bypass_using_mixed_ids(self):
        response = self.client.get('/api/v1/detector-admissions')
        self.assertEqual(response.status_code, 200)
        records = response.json()
        self.assertEqual({r['lane'] for r in records}, {'C', 'D'})
        before = self.client.get('/api/v1/scans').json()
        for row in records:
            for ids in ([row['id']], ['ohscanner.interface.ipc', row['id']]):
                body = {'repository_id': self.repo_id, 'revision': self.commit,
                        'include_paths': ['.'], 'detector_ids': ids}
                result = self.client.post('/api/v1/scans', headers=wb.HEADERS, json=body)
                self.assertEqual(result.status_code, 409, result.text)
                self.assertIn('admission blocked', result.text)
        self.assertEqual(self.client.get('/api/v1/scans').json(), before)

    def test_real_plan_explains_pending_without_running_them(self):
        before = self.client.get('/api/v1/scans').json()
        result = self.client.post('/api/v1/audit-plans', headers=wb.HEADERS,
            json={'repository_id': self.repo_id, 'revision': self.commit, 'include_paths': ['.']})
        self.assertEqual(result.status_code, 200, result.text)
        plan = result.json()
        pending = [d for d in plan['detectors'] if d.get('admission')]
        self.assertEqual(len(pending), 2)
        self.assertTrue(all(d['decision'] == 'blocked' for d in pending))
        self.assertEqual(self.client.get('/api/v1/scans').json(), before)
