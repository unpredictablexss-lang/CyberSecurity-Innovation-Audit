"""Owner integration: real fixed Git, bounded planning, API/Worker/CLI parity.

Authored controls verify wiring/evidence gates, not product accuracy.
"""
import json
import subprocess
import unittest
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

    def test_c_remains_blocked_while_d_requires_explicit_research_selection(self):
        c_id = 'ohscanner.ark.runtime.type_safety'
        r = self.client.post('/api/v1/scans', json=self.request(detector_ids=[c_id]), headers=fixtures.HEADERS)
        self.assertEqual(r.status_code, 409, r.text)
        self.assertIn('not-yet-approved', r.text)
        self.assertEqual(self.store.jobs(), [])

        d_id = 'ohscanner.data.sensitive_exposure'
        automatic = self.plan()
        d_row = next(row for row in automatic['detectors'] if row['id'] == d_id)
        self.assertEqual(d_row['decision'], 'skipped')
        self.assertIn('explicit_selection_required', d_row['reason_codes'])
        # Unknown-source fallback should preserve a name-based finding through
        # the same API -> Worker -> report path, without changing its status.
        (self.repo/'sensitive.cpp').write_text('''void logCredential(const char *password) {
            HILOG_INFO(1, "%{public}s", password);
        }
''')
        fixtures.git(self.repo, 'add', 'sensitive.cpp')
        fixtures.git(self.repo, 'commit', '-qm', 'unknown-source candidate fixture')
        self.commit = fixtures.git(self.repo, 'rev-parse', 'HEAD')
        plan = self.plan(detector_ids=[d_id])
        self.assertEqual(plan['suggested_detector_ids'], [d_id])
        job = self.scan(detector_ids=[d_id], expected_plan_sha256=plan['plan_sha256'])
        self.assertEqual(job['spec']['detector_ids'], [d_id])
        Worker(self.settings).run(once=True)
        completed = self.store.job(job['id'])
        self.assertEqual(completed['status'], 'completed_with_limitations')
        report = service.read_report(self.settings, completed)
        run = next(item for item in report['detector_runs'] if item['tool'] == d_id)
        self.assertEqual(run['status'], 'blocked')
        self.assertIn('No reviewed sensitive-source model', ' '.join(run['limitations']))
        self.assertTrue(any(item['rule_id'] == 'data.log.sensitive-value'
                            for item in run['diagnostics']))
        self.assertEqual(run['tool_version'], '0.14.0')
        self.assertEqual(report['validated_vulnerability'], 0)

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
