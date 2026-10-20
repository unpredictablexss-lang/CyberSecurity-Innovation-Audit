from dataclasses import replace
from hashlib import sha1
import unittest
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
from src.ohscanner.detectors.ark_runtime.model import DETECTOR_ID, RULE_ID, RuntimeTypeModel
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.detectors.catalog import build_registry
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from .support import case, context, unit, wrap, PREFIX


class ContractAdapterTests(unittest.TestCase):
    def bound_fixture(self, units):
        target = next((u for u in units if u.path == 'src/typedarray.cpp'), units[0])
        raw = target.text.encode('utf-8')
        blob = sha1(b'blob ' + str(len(raw)).encode('ascii') + bytes((0,)) + raw).hexdigest()
        revision = 'a' * 40
        repo = 'fixture/ark-runtime'
        model = replace(RuntimeTypeModel(), source_repository=repo,
                        target_bindings=((revision, target.path, blob, target.sha256),),
                        source_dependencies=())
        base = context(units)
        request = replace(base.request, repository=repo, commit=revision,
                          target_id='current-component:' + repo, profile_id='light-ast',
                          provenance='git_object', snapshot_sha256=snapshot_digest(tuple(sorted(units, key=lambda u: u.path))))
        facts = dict(base.shared_facts)
        facts['ast'] = dict(facts.get('ast', {}))
        facts['ast'][target.path] = dict(facts['ast'][target.path], parse_status=target.parse_status)
        facts['source_blob_oid'] = {
            unit.path: sha1(b'blob ' + str(len(unit.text.encode('utf-8'))).encode('ascii')
                            + bytes((0,)) + unit.text.encode('utf-8')).hexdigest()
            for unit in units
        }
        return replace(base, request=request, shared_facts=facts), model

    def run_detector(self, units):
        ctx, model = self.bound_fixture(units)
        return run_all_with_coverage(ctx, self._registry(model))

    def test_complete_fixture_produces_source_bound_v2_candidate(self):
        source = case('C03')
        reports, coverage = self.run_detector((source,))
        report = reports[0]
        self.assertEqual(report.schema_version, 2)
        self.assertEqual(report.tool, DETECTOR_ID)
        self.assertEqual(report.diagnostic_count, 1)
        finding = report.diagnostics[0]
        self.assertEqual(finding.rule_id, RULE_ID)
        self.assertEqual(finding.source_sha256, source.sha256)
        self.assertEqual(finding.severity, 'unassessed')
        self.assertEqual(finding.confidence, 'unassessed')
        self.assertTrue(coverage['detectors'][DETECTOR_ID]['evidence_obligations'][0]['obligations'])

    def test_exactly_bound_partial_fixture_preserves_candidate_and_unknown_scope(self):
        source = replace(case('C03'), parse_status='partial', parse_issues=('incomplete dependency',))
        reports, coverage = self.run_detector((source,))
        self.assertEqual(reports[0].status, 'blocked')
        self.assertEqual(reports[0].diagnostic_count, 1)
        self.assertEqual(coverage['detectors'][DETECTOR_ID]['coverage_counts']['partial'], 1)
        self.assertEqual(source.parse_status, 'partial')
        obligations = coverage['detectors'][DETECTOR_ID]['evidence_obligations'][0]['obligations']
        self.assertIn('parse_completeness_impact', [o['kind'] for o in obligations])

    def test_mixed_scope_retains_valid_complete_file_candidate(self):
        bad = replace(case('C04'), path='src/other.cpp', parse_status='partial')
        reports, coverage = self.run_detector((case('C03'), bad))
        self.assertEqual(reports[0].diagnostic_count, 1)
        self.assertEqual(coverage['detectors'][DETECTOR_ID]['coverage_counts'],
                         {'complete': 1, 'partial': 0, 'not_analyzed': 1, 'failed': 0})

    def test_aggregate_limited_does_not_discard_valid_local_candidate(self):
        code = wrap(PREFIX + 'Label good(GetEnvironment());\nLabel other(GetEnvironment());\n'
                    'BRANCH(count, &good, &other);\nBind(&good);\n'
                    'StoreTypedArrayElement(glue, output, count, input, inputTag);\nJump(exit);\n'
                    'Bind(&other);\nUNMODELED_IR();')
        reports, coverage = self.run_detector((unit(code),))
        self.assertEqual(reports[0].status, 'blocked')
        self.assertEqual(reports[0].diagnostic_count, 1)
        self.assertEqual(coverage['detectors'][DETECTOR_ID]['coverage_counts']['partial'], 1)

    def test_model_digest_binds_repository_revision_and_target_blob(self):
        model = RuntimeTypeModel()
        changed = replace(model, target_bindings=(
            model.target_bindings[0],
            (model.target_bindings[1][0], model.target_bindings[1][1],
             '0' * 40, model.target_bindings[1][3]),
        ))
        self.assertNotEqual(model.digest, changed.digest)

    def test_target_blob_mismatch_is_rejected_before_partial_analysis(self):
        source = replace(case('C03'), parse_status='partial')
        ctx, model = self.bound_fixture((source,))
        facts = dict(ctx.shared_facts)
        facts['source_blob_oid'] = dict(facts['source_blob_oid'], **{source.path: '0' * 40})
        ctx = replace(ctx, shared_facts=facts)
        reports, coverage = run_all_with_coverage(ctx, self._registry(model))
        self.assertEqual(reports[0].diagnostic_count, 0)
        self.assertEqual(coverage['detectors'][DETECTOR_ID]['coverage_counts']['not_analyzed'], 1)
        self.assertTrue(any('blob/SHA-256' in limitation for limitation in reports[0].limitations))

    def test_creator_dependency_blob_mismatch_is_not_analyzed(self):
        source = case('C03')
        ctx, model = self.bound_fixture((source,))
        model = replace(model, source_dependencies=((source.path, '0' * 40),))
        reports, coverage = run_all_with_coverage(ctx, self._registry(model))
        self.assertEqual(reports[0].diagnostic_count, 0)
        self.assertEqual(coverage['detectors'][DETECTOR_ID]['coverage_counts']['not_analyzed'], 1)
        self.assertTrue(any('creator dependency blob/SHA-256' in limitation
                            for limitation in reports[0].limitations))

    @staticmethod
    def _registry(model):
        registry = DetectorRegistry()
        registry.register(ArkRuntimeTypeSafetyDetector(model=model))
        return registry

    def test_source_content_hash_tamper_is_rejected(self):
        source = case('C03')
        object.__setattr__(source, 'text', source.text + '\n// tampered\n')
        result = analyze_unit(source)
        self.assertEqual(result.status, 'failed')
        self.assertIn('source_hash_mismatch', result.limitations)

    def test_missing_facts_are_not_bypassed_in_direct_adapter(self):
        source = case('C03')
        ctx, model = self.bound_fixture((source,))
        ctx = replace(ctx, shared_facts={})
        result = ArkRuntimeTypeSafetyDetector(model=model).detect(ctx, (source,))
        self.assertEqual(result.status, 'blocked')
        self.assertFalse(result.findings)

    def test_direct_adapter_rejects_mixed_source_context(self):
        provided = case('C04')
        supplied = case('C03')
        ctx, model = self.bound_fixture((provided,))
        with self.assertRaisesRegex(ValueError, 'outside_bound_context'):
            ArkRuntimeTypeSafetyDetector(model=model).detect(ctx, (supplied,))

    def test_catalog_allows_explicit_selection_but_keeps_c_out_of_defaults(self):
        from src.ohscanner.detectors.catalog import default_detector_ids
        self.assertNotIn(DETECTOR_ID, default_detector_ids())
        registry = build_registry((DETECTOR_ID,))
        self.assertEqual(registry.detectors()[0].detector_id, DETECTOR_ID)

    def test_same_inputs_produce_stable_ids(self):
        first, _ = self.run_detector((case('C03'),))
        second, _ = self.run_detector((case('C03'),))
        self.assertEqual(first[0].diagnostics[0].diagnostic_id, second[0].diagnostics[0].diagnostic_id)

    def test_visible_incompatible_store_signature_is_unknown(self):
        code = case('C03').text + '\nnamespace panda::ecmascript::kungfu {\n'
        code += 'GateRef BuiltinsTypedArrayStubBuilder::StoreTypedArrayElement(GateRef x) { return x; }\n}\n'
        result = analyze_unit(unit(code))
        self.assertIn('sink_definition_signature_mismatch', result.limitations)
        self.assertFalse(result.observations)


if __name__ == '__main__':
    unittest.main()
