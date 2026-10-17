from dataclasses import replace
import unittest
from src.ohscanner.detectors.ark_runtime.analysis import analyze_unit
from src.ohscanner.detectors.ark_runtime.detector import ArkRuntimeTypeSafetyDetector
from src.ohscanner.detectors.ark_runtime.model import DETECTOR_ID, RULE_ID
from src.ohscanner.detectors.catalog import build_registry
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage
from .support import case, context, unit, wrap, PREFIX


class ContractAdapterTests(unittest.TestCase):
    def run_detector(self, units):
        ctx = context(units)
        registry = DetectorRegistry()
        registry.register(ArkRuntimeTypeSafetyDetector())
        return run_all_with_coverage(ctx, registry)

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

    def test_partial_is_blocked_before_detector_execution(self):
        source = replace(case('C03'), parse_status='partial', parse_issues=('incomplete dependency',))
        reports, coverage = self.run_detector((source,))
        self.assertEqual(reports[0].status, 'blocked')
        self.assertEqual(reports[0].diagnostic_count, 0)
        self.assertEqual(coverage['detectors'][DETECTOR_ID]['coverage_counts']['not_analyzed'], 1)
        self.assertEqual(source.parse_status, 'partial')

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

    def test_source_content_hash_tamper_is_rejected(self):
        source = case('C03')
        object.__setattr__(source, 'text', source.text + '\n// tampered\n')
        result = analyze_unit(source)
        self.assertEqual(result.status, 'failed')
        self.assertIn('source_hash_mismatch', result.limitations)

    def test_missing_facts_are_not_bypassed_in_direct_adapter(self):
        source = case('C03')
        ctx = replace(context((source,)), shared_facts={})
        result = ArkRuntimeTypeSafetyDetector().detect(ctx, (source,))
        self.assertEqual(result.status, 'blocked')
        self.assertFalse(result.findings)

    def test_direct_adapter_rejects_mixed_source_context(self):
        with self.assertRaisesRegex(ValueError, 'outside_bound_context'):
            ArkRuntimeTypeSafetyDetector().detect(context((case('C04'),)), (case('C03'),))

    def test_catalog_remains_unmodified_and_not_enabled(self):
        with self.assertRaises(ValueError):
            build_registry((DETECTOR_ID,))

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
