"""Owner integration: truthful coverage, validated evidence, real CLI boundary."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.ohscanner.contracts import (
    DetectorFinding, DetectorRun, EvidenceObligation, ScanContext, ScanRequest, SourceUnit,
)
from src.ohscanner.detectors.catalog import build_registry, catalog_metadata
from src.ohscanner.detectors.interface.detector import IpcInterfaceDetector
from src.ohscanner.detectors.interface.m2_adapter import M2IpcInterfaceDetector
from src.ohscanner.execution import run_fixed_commit_scan, run_reviewed_detectors
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from src.parser.ast import parse_source

ROOT = Path(__file__).resolve().parents[1]
POSITIVE = (ROOT / 'tests/fixtures/ipc/auth_positive.cpp').read_text()
ID = 'ohscanner.interface.ipc'


def unit(path, text, status='complete'):
    return SourceUnit(path, 'cpp', text, hashlib.sha256(text.encode()).hexdigest(), status)


def context(units):
    units = tuple(sorted(units, key=lambda u: u.path))
    request = ScanRequest('owner-test', 'fixture/owner', 'synthetic', snapshot_digest(units),
                          'current-component:fixture/owner')
    return ScanContext(request, units, {'ast': {u.path: {} for u in units}})


class FixedDetector:
    detector_id = 'ohscanner.test.owner'
    version = '1'
    required_facts = ()
    supported_languages = ('cpp',)

    def __init__(self, result):
        self.result = result

    def detect(self, context, units):
        return self.result


def execute(ctx, result):
    registry = DetectorRegistry()
    registry.register(FixedDetector(result))
    reports, sidecar = run_all_with_coverage(ctx, registry)
    return reports[0], sidecar['detectors'][FixedDetector.detector_id]


class CoverageEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.ctx = context((unit('a.cpp', 'int a;'), unit('b.cpp', 'int b;', 'partial'),
                            unit('c.cpp', 'int c;', 'failed')))
        self.finding = DetectorFinding('b.cpp', 1, 'test.rule', 'candidate',
            evidence_obligations=(EvidenceObligation('guard', 'Establish an effective guard.'),))
        self.run = DetectorRun(FixedDetector.detector_id, '1', 'blocked', ('a.cpp', 'b.cpp'),
            (self.finding,), file_outcomes=(('a.cpp', 'complete'), ('b.cpp', 'partial'),
                                           ('c.cpp', 'not_analyzed')))

    def test_blocked_preserves_inspection_counts_and_partial_obligations(self):
        report, data = execute(self.ctx, self.run)
        self.assertEqual(report.status, 'blocked')
        self.assertEqual(report.scope_files, 2)
        self.assertEqual(report.scope_loc, 2)
        self.assertEqual(data['coverage_counts'], {'complete': 1, 'partial': 1, 'not_analyzed': 1, 'failed': 0})
        self.assertEqual(data['partially_inspected_files'], ['b.cpp'])
        self.assertEqual(data['not_analyzed_files'], ['c.cpp'])
        proof = data['evidence_obligations'][0]
        self.assertEqual(proof['analysis_status'], 'partial')
        self.assertEqual(proof['obligations'][0]['status'], 'unknown')
        self.assertEqual(proof['source_binding']['source_sha256'], self.ctx.units[1].sha256)
        self.assertEqual(proof['source_binding']['snapshot_sha256'], self.ctx.request.snapshot_sha256)

    def test_completed_execution_can_have_partial_analysis(self):
        report, data = execute(self.ctx, replace(self.run, status='completed'))
        self.assertEqual(report.status, 'completed')
        self.assertEqual(data['status'], 'partial')
        self.assertEqual(report.scope_files, 2)

    def test_validated_failed_run_keeps_already_inspected_evidence(self):
        report, data = execute(self.ctx, replace(self.run, status='failed'))
        self.assertEqual(report.status, 'failed')
        self.assertEqual(data['status'], 'failed')
        self.assertEqual(report.diagnostic_count, 1)
        self.assertEqual(len(data['evidence_obligations']), 1)

    def test_legacy_blocked_inspection_is_not_complete(self):
        report, data = execute(self.ctx, replace(self.run, file_outcomes=()))
        self.assertEqual(report.scope_files, 2)
        self.assertEqual(data['analyzed_files'], [])
        self.assertEqual(data['partially_inspected_files'], ['a.cpp', 'b.cpp'])

    def test_incomplete_parse_cannot_be_promoted_by_file_outcome(self):
        bad = replace(self.run, file_outcomes=(('a.cpp', 'complete'), ('b.cpp', 'complete'),
                                                ('c.cpp', 'not_analyzed')))
        report, data = execute(self.ctx, bad)
        self.assertEqual(report.status, 'failed')
        self.assertEqual(report.diagnostic_count, 0)
        self.assertEqual(data['evidence_obligations'], [])

    def test_invalid_scope_location_or_outcome_discards_untrusted_evidence(self):
        variants = [
            replace(self.run, findings=(replace(self.finding, file='c.cpp'),)),
            replace(self.run, findings=(replace(self.finding, line=999),)),
            replace(self.run, file_outcomes=(('a.cpp', 'complete'),)),
            replace(self.run, analyzed_files=('a.cpp', 'b.cpp', 'outside.cpp')),
        ]
        for bad in variants:
            with self.subTest(run=bad):
                report, data = execute(self.ctx, bad)
                self.assertEqual(report.status, 'failed')
                self.assertEqual(report.diagnostic_count, 0)
                self.assertEqual(data['evidence_obligations'], [])

    def test_source_manifest_mismatch_is_rejected_before_execution(self):
        bad_request = replace(self.ctx.request, snapshot_sha256='0' * 64)
        with self.assertRaisesRegex(ValueError, 'manifest'):
            execute(replace(self.ctx, request=bad_request), self.run)

    def test_empty_obligations_are_explicit_not_synthesized_proof(self):
        report, data = execute(self.ctx, replace(self.run, findings=(replace(
            self.finding, evidence_obligations=()),)))
        self.assertEqual(report.diagnostic_count, 1)
        self.assertEqual(data['evidence_obligations'][0]['obligations'], [])


class IpcSinglePassTests(unittest.TestCase):
    def test_one_engine_call_keeps_complete_partial_and_missing_units_separate(self):
        ctx = context((unit('a.cpp', POSITIVE), unit('b.cpp', POSITIVE + '\nint broken( {', 'partial'),
                       unit('c.cpp', 'int c;', 'failed')))
        original = IpcInterfaceDetector.detect
        calls = []
        def spy(detector, shared, units):
            calls.append(tuple(u.path for u in units))
            return original(detector, shared, units)
        with patch.object(IpcInterfaceDetector, 'detect', spy):
            reports, sidecar = run_all_with_coverage(ctx, build_registry((ID,)))
        self.assertEqual(calls, [('a.cpp', 'b.cpp')])
        data = sidecar['detectors'][ID]
        self.assertEqual(reports[0].status, 'completed')
        self.assertEqual(data['coverage_counts'], {'complete': 1, 'partial': 1, 'not_analyzed': 1, 'failed': 0})
        partial = [p for p in data['evidence_obligations'] if p['file'] == 'b.cpp']
        self.assertTrue(partial)
        self.assertTrue(all(any(o['kind'] == 'parse_completeness_impact' and o['status'] == 'unknown'
                                for o in p['obligations']) for p in partial))

    def test_all_unavailable_is_blocked_with_no_claimed_inspection(self):
        ctx = context((unit('failed.cpp', 'bad', 'failed'),))
        reports, sidecar = run_all_with_coverage(ctx, build_registry((ID,)))
        self.assertEqual(reports[0].status, 'blocked')
        self.assertEqual(reports[0].scope_files, 0)
        self.assertEqual(sidecar['detectors'][ID]['not_analyzed_files'], ['failed.cpp'])

    def test_catalog_exposes_one_interface_identity_not_workaround_variant(self):
        self.assertEqual(catalog_metadata()[ID]['kind'], 'research_candidate')
        with self.assertRaises(ValueError):
            build_registry((ID + '.complete-ast',))


class FormalCliTests(unittest.TestCase):
    def test_cli_and_programmatic_registry_agree_on_pinned_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repo = root / 'repo'
            repo.mkdir()
            def git(*args):
                return subprocess.check_output(['git', '-C', str(repo), *args], text=True).strip()
            git('init', '-q')
            git('config', 'user.name', 'Owner integration test')
            git('config', 'user.email', 'test@example.invalid')
            (repo / 'a.cpp').write_text(POSITIVE)
            (repo / 'b.cpp').write_text(POSITIVE + '\nint broken( {')
            (repo / 'bridge.ets').write_text('export class Bridge {}')
            git('add', '.')
            git('commit', '-qm', 'pinned')
            commit = git('rev-parse', 'HEAD')
            direct = run_reviewed_detectors(repo, 'fixture/owner-cli', commit, ('.',), build_registry((ID,)))
            output = root / 'cli.json'
            markdown = root / 'cli.md'
            command = [sys.executable, '-m', 'src.cli', 'ohscan-run', '--repo-dir', str(repo),
                       '--repository', 'fixture/owner-cli', '--commit', commit, '--detector', ID,
                       '--json-out', str(output), '--md-out', str(markdown)]
            done = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=60)
            self.assertEqual(done.returncode, 0, done.stderr)
            actual = json.loads(output.read_text())
            self.assertEqual(actual['detector_coverage'], direct['detector_coverage'])
            self.assertEqual(actual['detector_runs'][0]['diagnostics'], direct['detector_runs'][0]['diagnostics'])
            self.assertEqual(actual['files_in_scope_without_a_claiming_detector'], ['bridge.ets'])
            self.assertEqual(actual['status'], 'completed_with_limitations')
            self.assertEqual(actual['validated_vulnerability'], 0)
            self.assertEqual(actual['detector_runs'][0]['schema_version'], 2)
            rendered = markdown.read_text()
            self.assertIn('Complete | Partial | Not analyzed', rendered)
            self.assertIn('parse_completeness_impact=unknown', rendered)
            self.assertIn('bridge.ets', rendered)
            # Working tree changes cannot alter this pinned source result.
            (repo / 'a.cpp').write_text('int changed;')
            after = run_fixed_commit_scan(repo, 'fixture/owner-cli', commit, ('.',), (ID,),
                                          root / 'after.json', root / 'after.md')
            self.assertEqual(actual['snapshot_sha256'], after['snapshot_sha256'])
            self.assertEqual(actual['detector_runs'][0]['diagnostics'], after['detector_runs'][0]['diagnostics'])


if __name__ == '__main__':
    unittest.main()
