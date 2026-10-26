"""No implicit network. Supply the already-synced source Git store explicitly."""
import os
from pathlib import Path
import subprocess
import unittest

from research.experiments.ark_runtime.c2_20261017.replay import MANIFEST, pinned_context
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
from src.ohscanner.detectors.ark_runtime.model import RuntimeTypeModel, CALLER
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
import json


@unittest.skipUnless(os.environ.get('OHSCANNER_ARK_REPO'), 'Pinned Ark Git store not supplied; no implicit fetch')
class HistoricalPairTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        repo = os.environ.get('OHSCANNER_ARK_REPO')
        if repo:
            for commit in ('830e85b40240677039719fcbf14f721ad3b19050',
                           'a0e30483ab3e4aead67ecfb5c708489915e447f9'):
                if subprocess.run(['git', '-C', repo, 'cat-file', '-e', commit + '^{commit}'],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
                    raise unittest.SkipTest('Historical C1 Git objects are absent from supplied component store')

    def run_version(self, index):
        manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
        entry = manifest['sources'][index]
        ctx, _, _, _, _ = pinned_context(Path(os.environ['OHSCANNER_ARK_REPO']), entry['commit'], entry['source_sha256'])
        self.assertEqual(ctx.units[0].parse_status, 'partial')
        result = analyze_unit(ctx.units[0], model=RuntimeTypeModel(caller_profiles=()), research_partial=True)
        self.assertTrue(all(o.symbol == CALLER for o in result.observations))
        return result

    def test_C01_pinned_before_has_origin_candidate(self):
        result = self.run_version(0)
        self.assertEqual([o.kind for o in result.observations], ['candidate'])
        self.assertEqual(result.file_outcome, 'partial')

    def test_C02_pinned_fix_has_no_rule_candidate(self):
        result = self.run_version(1)
        self.assertEqual([o.kind for o in result.observations], ['matched'])
        self.assertFalse(any(o.kind == 'candidate' for o in result.observations))
        self.assertEqual(result.file_outcome, 'partial')

    def test_exact_parent_and_fix_through_runner_keep_candidate_and_coverage_distinct(self):
        model = RuntimeTypeModel(caller_profiles=())
        registry = DetectorRegistry()
        registry.register(ArkRuntimeTypeSafetyDetector(model=model))
        expected = (('candidate', True), ('matched', False))
        for index, (expected_kind, has_candidate) in enumerate(expected):
            manifest = json.loads(MANIFEST.read_text(encoding='utf-8'))
            source = manifest['sources'][index]
            context, _, _, _, _ = pinned_context(
                Path(os.environ['OHSCANNER_ARK_REPO']), source['commit'], source['source_sha256'])
            report_set, coverage = run_all_with_coverage(context, registry)
            report = report_set[0]
            findings = [item for item in report.diagnostics
                        if item.rule_id == 'ark.runtime.typedarray-store-type-origin']
            self.assertEqual(bool(findings), has_candidate)
            if has_candidate:
                self.assertTrue(all(item.message.startswith('Candidate only:') for item in findings))
                self.assertEqual(findings[0].source_sha256, source['source_sha256'])
            entry = coverage['detectors']['ohscanner.ark.runtime.type_safety']
            self.assertEqual(entry['coverage_counts']['partial'], 1)
            self.assertEqual(report.status, 'blocked')


@unittest.skipUnless(os.environ.get('OHSCANNER_ARK_REPO'),
                     'Component Git store not supplied; no implicit fetch')
class CurrentComponentRunnerBindingTests(unittest.TestCase):
    def test_bound_current_component_is_explicitly_selected_but_partial_stays_unknown(self):
        from src.ohscanner.indexing import prepare_git_context

        repo = Path(os.environ['OHSCANNER_ARK_REPO'])
        model = RuntimeTypeModel()
        path = 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'
        context, _, _, _, _ = prepare_git_context(
            repo, model.source_repository, 'a65a2853ccae13da167d9aa4720ab8b11ec16656', (path,))
        self.assertEqual(context.request.commit, 'a65a2853ccae13da167d9aa4720ab8b11ec16656')
        self.assertEqual(context.request.provenance, 'git_object')
        self.assertEqual(context.shared_facts['source_blob_oid'][path],
                         '68fb3b0adc4f9062889a861be51b7be90362e37a')
        self.assertEqual(context.units[0].sha256,
                         '76418526220ea039410d5a214b03d923436ce9441d9852538832b3664c41bd3c')

        registry = DetectorRegistry()
        registry.register(ArkRuntimeTypeSafetyDetector(model=model))
        reports, coverage = run_all_with_coverage(context, registry)
        entry = coverage['detectors']['ohscanner.ark.runtime.type_safety']
        self.assertEqual(reports[0].status, 'blocked')
        self.assertFalse(reports[0].diagnostics)
        self.assertEqual(entry['coverage_counts']['not_analyzed'], 1)
        self.assertEqual(entry['coverage_counts']['complete'], 0)
        self.assertEqual(entry['coverage_counts']['partial'], 0)
        self.assertEqual(entry['not_analyzed_files'], [path])
        self.assertEqual(model.version, '0.6.3')
        self.assertTrue(any(
            'tree=8781f036a3e7e04d8e0b34970d5f623b42875016'
            in limitation
            and 'snapshot_sha256=7f1c19c5ba21a311fba7f018df8fff077c6c9a60ee81c3ce348bb5b0a9f017d2'
            in limitation
            and 'comparison_manifest_sha256=c920f31bc6fe4c05d0d64b210b26dacc8b01d277aeb86ca552ddf52ce83f8d2d'
            in limitation and 'model_sha256=' + model.digest in limitation
            for limitation in reports[0].limitations))

    def test_current_component_rules_remain_default_off_and_require_explicit_selection(self):
        from src.ohscanner.detectors.catalog import default_detector_ids, build_registry

        detector_id = 'ohscanner.ark.runtime.type_safety'
        self.assertNotIn(detector_id, default_detector_ids())
        detector = build_registry((detector_id,)).detectors()[0]
        self.assertEqual(detector.detector_id, detector_id)


@unittest.skipUnless(os.environ.get('OHSCANNER_ARK_REPO'),
                     'Component Git store not supplied; no implicit fetch')
class CurrentComponentWrongVersionTests(unittest.TestCase):
    def test_same_path_at_unbound_commit_is_not_analyzed(self):
        from src.ohscanner.indexing import prepare_git_context

        repo = Path(os.environ['OHSCANNER_ARK_REPO'])
        path = 'ecmascript/compiler/builtins/builtins_typedarray_stub_builder.cpp'
        commit = subprocess.check_output(
            ['git', '-C', str(repo), 'rev-parse', 'a65a2853ccae13da167d9aa4720ab8b11ec16656^'],
            text=True).strip()
        context, _, _, _, _ = prepare_git_context(
            repo, RuntimeTypeModel().source_repository, commit, (path,))
        self.assertNotEqual(commit, 'a65a2853ccae13da167d9aa4720ab8b11ec16656')
        registry = DetectorRegistry()
        registry.register(ArkRuntimeTypeSafetyDetector())
        reports, coverage = run_all_with_coverage(context, registry)
        entry = coverage['detectors']['ohscanner.ark.runtime.type_safety']
        self.assertEqual(reports[0].status, 'blocked')
        self.assertFalse(reports[0].diagnostics)
        self.assertEqual(entry['coverage_counts']['not_analyzed'], 1)


if __name__ == '__main__':
    unittest.main()
