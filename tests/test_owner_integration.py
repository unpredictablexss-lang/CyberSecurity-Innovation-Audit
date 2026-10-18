"""Owner integration: real fixed Git, bounded planning, API/Worker/CLI parity.

Authored controls verify wiring/evidence gates, not product accuracy.
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from tests import test_workbench as fixtures
from src.ohscanner.execution import run_fixed_commit_scan
from src.workbench import service
from src.workbench.worker import Worker


@unittest.skipIf(fixtures.create_app is None, 'optional web dependencies unavailable')
class OwnerIntegrationTests(unittest.TestCase):
    setUp = fixtures.WorkbenchTests.setUp

    def request(self, **extra):
        return {'repository_id': self.repo_id, 'revision': self.commit,
                'include_paths': ['.'], **extra}

    def plan(self, **extra):
        r = self.client.post('/api/v1/audit-plans', json=self.request(**extra), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 200, r.text)
        return r.json()

    def scan(self, **extra):
        r = self.client.post('/api/v1/scans', json=self.request(**extra), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 201, r.text)
        return r.json()

    def test_automatic_plan_is_frozen_and_worker_matches_cli(self):
        plan = self.plan()
        self.assertEqual(plan['selection_mode'], 'automatic')
        self.assertEqual(len(plan['suggested_detector_ids']), 8)
        self.assertEqual(plan['execution_status'], 'not_run')
        null = next(d for d in plan['detectors'] if d['id']=='ohscanner.cpp.null_dereference')
        self.assertEqual(null['reason_codes'], ['explicit_selection_required'])
        self.assertIn('partial.cpp', [f['file'] for f in plan['parse_limitations']])
        job = self.scan(expected_plan_sha256=plan['plan_sha256'])
        self.assertEqual(job['spec']['audit_plan'], plan)
        self.assertEqual(job['spec']['plan_sha256'], plan['plan_sha256'])
        Worker(self.settings).run(once=True)
        job = self.store.job(job['id'])
        self.assertEqual(job['status'], 'completed_with_limitations', job)
        report = service.read_report(self.settings, job)
        self.assertEqual(report['audit_plan'], plan)
        cli = run_fixed_commit_scan(self.repo, 'fixture/sample', self.commit, ('.',),
                                    None, self.root/'cli.json', self.root/'cli.md')
        self.assertEqual(cli['audit_plan'], plan)
        for a, b in zip(cli['detector_runs'], report['detector_runs']):
            for field in ('tool', 'tool_version', 'status', 'diagnostics', 'parsing'):
                self.assertEqual(a[field], b[field])
        self.assertEqual(cli['detector_coverage'], report['detector_coverage'])
        self.assertGreater(report['diagnostic_count'], 0)
        self.assertEqual(report['validated_vulnerability'], 0)
        for item in service.findings(report):
            self.assertTrue(item['evidence']['obligations'])

    def test_js_only_auto_selects_script_detector_and_real_eval_candidate(self):
        (self.repo/'dynamic.js').write_text('export function run(input) { eval(input); }\n')
        fixtures.git(self.repo, 'add', '.')
        fixtures.git(self.repo, 'commit', '-qm', 'script control')
        self.commit = fixtures.git(self.repo, 'rev-parse', 'HEAD')
        plan = self.plan(include_paths=['dynamic.js'])
        self.assertEqual(plan['suggested_detector_ids'], ['ohscanner.oh.arkts_js'])
        self.assertTrue(all(d['decision']=='skipped' for d in plan['detectors']
                            if d['id'] != 'ohscanner.oh.arkts_js' and not d.get('admission')))
        self.assertTrue(all(d['decision']=='blocked' for d in plan['detectors'] if d.get('admission')))
        job = self.scan(include_paths=['dynamic.js'])
        Worker(self.settings).run(once=True)
        report = service.read_report(self.settings, self.store.job(job['id']))
        self.assertEqual(len(report['detector_runs']), 1)
        run = report['detector_runs'][0]
        self.assertEqual(run['tool'], 'ohscanner.oh.arkts_js')
        self.assertTrue(any(d['rule_id']=='ohscanner.js.dangerous_eval' for d in run['diagnostics']))

    def test_legacy_explicit_selection_still_runs_only_requested_ids(self):
        job = self.scan(detector_ids=fixtures.IDS)
        self.assertEqual(job['spec']['detector_ids'], fixtures.IDS)
        self.assertEqual(job['spec']['audit_plan']['selection_mode'], 'explicit')
        Worker(self.settings).run(once=True)
        report = service.read_report(self.settings, self.store.job(job['id']))
        self.assertEqual({r['tool'] for r in report['detector_runs']}, set(fixtures.IDS))

    def test_preview_does_not_enqueue_and_empty_selection_is_not_auto(self):
        plan = self.plan(detector_ids=[])
        self.assertEqual(plan['suggested_detector_ids'], [])
        self.assertEqual(plan['status'], 'blocked')
        self.assertEqual(self.store.jobs(), [])
        r = self.client.post('/api/v1/scans', json=self.request(detector_ids=[]), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 422)
        self.assertEqual(self.store.jobs(), [])

    def test_c_requires_explicit_selection_and_is_not_applicable_to_other_repos(self):
        from src.ohscanner.detectors.catalog import default_detector_ids
        ident = 'ohscanner.ark.runtime.type_safety'
        self.assertNotIn(ident, default_detector_ids())
        r = self.client.post('/api/v1/scans', json=self.request(detector_ids=[ident]), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 201, r.text)
        Worker(self.settings).run(once=True)
        report = service.read_report(self.settings, self.store.job(r.json()['id']))
        run = next(item for item in report['detector_runs'] if item['tool'] == ident)
        self.assertEqual(run['status'], 'blocked')
        self.assertEqual(run['diagnostics'], [])
        self.assertEqual(report['validated_vulnerability'], 0)

    def test_c_rejects_duplicate_detector_and_duplicate_path_inputs(self):
        ident = 'ohscanner.ark.runtime.type_safety'
        duplicate_detector = self.client.post(
            '/api/v1/scans', json=self.request(detector_ids=[ident, ident]), headers=fixtures.HEADERS)
        self.assertEqual(duplicate_detector.status_code, 409, duplicate_detector.text)
        duplicate_path = self.client.post(
            '/api/v1/scans', json=self.request(include_paths=['.', '.']), headers=fixtures.HEADERS)
        self.assertEqual(duplicate_path.status_code, 409, duplicate_path.text)
        self.assertEqual(self.store.jobs(), [])

    def test_d_stays_blocked_for_production_selection(self):
        ident = 'ohscanner.data.sensitive_exposure'
        r = self.client.post('/api/v1/scans', json=self.request(detector_ids=[ident]), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 409, r.text)
        self.assertIn('not-yet-approved', r.text)
        self.assertEqual(self.store.jobs(), [])

    def test_changed_branch_after_preview_requires_new_plan(self):
        plan = self.plan(revision='HEAD')
        (self.repo/'later.cpp').write_text('int later(){ return 0; }\n')
        fixtures.git(self.repo, 'add', '.')
        fixtures.git(self.repo, 'commit', '-qm', 'branch advanced')
        r = self.client.post('/api/v1/scans', json=self.request(
            revision='HEAD', expected_plan_sha256=plan['plan_sha256']), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 409, r.text)
        self.assertEqual(self.store.jobs(), [])

    def test_tampered_queued_plan_fails_without_published_result(self):
        job = self.scan()
        spec = job['spec']; spec['audit_plan']['metadata_sha256'] = '0'*64
        with self.store.connect() as db:
            db.execute('UPDATE jobs SET spec=? WHERE id=?', (json.dumps(spec), job['id']))
        Worker(self.settings).run(once=True)
        result = self.store.job(job['id'])
        self.assertEqual(result['status'], 'failed')
        self.assertIsNone(result['report_sha256'])
        log = service.artifact_dir(self.settings, job['id'])/'worker.log'
        self.assertIn('Frozen audit plan drifted', log.read_text())

    def test_planning_timeout_does_not_enqueue(self):
        run = subprocess.run
        def timeout_only_planner(args, **kwargs):
            if 'src.workbench.plan_child' in args:
                raise subprocess.TimeoutExpired(args, 35)
            return run(args, **kwargs)
        with patch('src.workbench.service.subprocess.run', side_effect=timeout_only_planner):
            r = self.client.post('/api/v1/scans', json=self.request(), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 409)
        self.assertIn('deadline exceeded', r.text)
        self.assertEqual(self.store.jobs(), [])

    def test_client_header_and_cross_origin_still_required_for_plan_preview(self):
        r = self.client.post('/api/v1/audit-plans', json=self.request())
        self.assertEqual(r.status_code, 403)
        r = self.client.post('/api/v1/audit-plans', json=self.request(),
                             headers={**fixtures.HEADERS, 'origin':'https://untrusted.example'})
        self.assertEqual(r.status_code, 403)

    def test_registered_null_rule_requires_explicit_selection(self):
        plan = self.plan(detector_ids=['ohscanner.cpp.null_dereference'])
        self.assertEqual(plan['suggested_detector_ids'], ['ohscanner.cpp.null_dereference'])
        self.assertEqual(plan['selection_mode'], 'explicit')

    def test_report_budget_rejects_before_creating_truncated_artifact(self):
        from src.ohscanner.execution import write_report_json
        target = self.root/'bounded.json'
        with patch('src.ohscanner.execution.MAX_REPORT_BYTES', 8):
            with self.assertRaisesRegex(ValueError, 'publication budget'):
                write_report_json({'too_large': 'sample'}, target)
        self.assertFalse(target.exists())
        self.assertFalse(target.with_suffix('.json.tmp').exists())


@unittest.skipIf(fixtures.create_app is None, 'optional web dependencies unavailable')
@unittest.skipUnless(os.environ.get('OHSCANNER_ARK_REPO'),
                     'Pinned Ark Git store not supplied; no implicit fetch')
class ArkRuntimeOwnerParityTests(unittest.TestCase):
    """Compare CLI and API/Worker on the same exact reviewed component snapshot."""

    detector_id = 'ohscanner.ark.runtime.type_safety'
    repository = 'openharmony/arkcompiler_ets_runtime'
    commit = 'a65a2853ccae13da167d9aa4720ab8b11ec16656'
    path = 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'

    def setUp(self):
        self.repo = Path(os.environ['OHSCANNER_ARK_REPO']).resolve()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.settings = fixtures.Settings(self.root / 'data', (self.repo.parent,))
        self.app = fixtures.create_app(self.settings)
        self.client = fixtures.TestClient(self.app)
        self.addCleanup(self.client.close)
        self.store = self.app.state.store
        self.assertEqual(fixtures.git(self.repo, 'rev-parse', self.commit), self.commit)
        self.assertEqual(fixtures.git(self.repo, 'rev-parse', self.commit + ':' + self.path),
                         '68fb3b0adc4f9062889a861be51b7be90362e37a')
        response = self.client.post(
            '/api/v1/repositories',
            json={'name': self.repository, 'path': str(self.repo)}, headers=fixtures.HEADERS)
        self.assertEqual(response.status_code, 201, response.text)
        self.repo_id = response.json()['id']

    def test_explicit_c_selection_has_identical_cli_and_worker_output(self):
        from src.ohscanner.detectors.catalog import default_detector_ids

        self.assertNotIn(self.detector_id, default_detector_ids())
        request = {'repository_id': self.repo_id, 'revision': self.commit,
                   'include_paths': [self.path], 'detector_ids': [self.detector_id]}
        plan_response = self.client.post('/api/v1/audit-plans', json=request, headers=fixtures.HEADERS)
        self.assertEqual(plan_response.status_code, 200, plan_response.text)
        plan = plan_response.json()
        self.assertEqual(plan['selection_mode'], 'explicit')
        self.assertEqual(plan['suggested_detector_ids'], [self.detector_id])

        queued = self.client.post('/api/v1/scans', json={**request,
            'expected_plan_sha256': plan['plan_sha256']}, headers=fixtures.HEADERS)
        self.assertEqual(queued.status_code, 201, queued.text)
        self.assertEqual(queued.json()['spec']['detector_ids'], [self.detector_id])
        fixtures.Worker(self.settings).run(once=True)
        job = self.store.job(queued.json()['id'])
        self.assertIn(job['status'], {'completed', 'completed_with_limitations'}, job)
        worker_report = service.read_report(self.settings, job)
        cli_report = run_fixed_commit_scan(
            self.repo, self.repository, self.commit, (self.path,), (self.detector_id,),
            self.root / 'cli.json', self.root / 'cli.md', expected_plan=plan)

        self.assertEqual([row['tool'] for row in worker_report['detector_runs']], [self.detector_id])
        self.assertEqual([row['tool'] for row in cli_report['detector_runs']], [self.detector_id])
        self.assertEqual(worker_report['audit_plan']['suggested_detector_ids'],
                         cli_report['audit_plan']['suggested_detector_ids'])
        self.assertEqual(worker_report['detector_coverage'], cli_report['detector_coverage'])
        self.assertEqual(worker_report['detector_runs'][0]['diagnostics'],
                         cli_report['detector_runs'][0]['diagnostics'])
        entry = worker_report['detector_coverage']['detectors'][self.detector_id]
        self.assertEqual(entry['applicable_files'], 1)
        self.assertEqual(sum(entry['coverage_counts'].values()), entry['applicable_files'])
        self.assertEqual(entry['coverage_counts']['complete'], 0)
        self.assertEqual(entry['coverage_counts']['failed'], 0)
        self.assertEqual(entry['coverage_counts']['partial'] +
                         entry['coverage_counts']['not_analyzed'], 1)
        self.assertEqual(worker_report['detector_runs'][0]['schema_version'], 2)
        self.assertEqual(worker_report['detector_runs'][0]['status'], 'blocked')
        self.assertEqual(worker_report['detector_runs'][0]['diagnostics'], [])
        self.assertEqual(entry['source_sha256'][self.path],
                         '76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c')
        self.assertEqual(worker_report['_workbench']['source_inventory'], [
            {'file': self.path, 'blob': '68fb3b0adc4f9062889a861be51b7be90362e37a',
             'sha256': '76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c'}])
        self.assertEqual(cli_report['validated_vulnerability'], 0)
        self.assertEqual(worker_report['validated_vulnerability'], 0)
