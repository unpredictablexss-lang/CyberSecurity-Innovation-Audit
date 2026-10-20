"""Named D86 semantic boundaries; heuristic matches are never independent truth labels."""
import unittest
from tests.detectors.data import test_sensitive_exposure as support
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector


def analyze(body, prefix='', partial=None):
    context = support.SensitiveTests().context(
        prefix + 'void f(const char *password) {' + body + '}', partial=partial)
    return SensitiveExposureDetector().detect(context, context.units)


class D86HeuristicSemanticsTests(unittest.TestCase):
    def test_unknown_values_are_not_public_merely_because_explicit_flow_is_empty(self):
        # Literal spelling alone cannot prove this value is an attribute key or
        # a display marker instead of an actual hard-coded credential.
        cases = {
            'unbound_parameter': 'HILOG_INFO(1,"%{public}s",password);',
            'hardcoded_secret': 'password="actual-secret"; HILOG_INFO(1,"%{public}s",password);',
            'ambiguous_property_spelling': 'password="password"; HILOG_INFO(1,"%{public}s",password);',
            'ambiguous_redaction_spelling': 'password="<redacted>"; HILOG_INFO(1,"%{public}s",password);',
            'unknown_return': 'password=GetOpaqueValue(); HILOG_INFO(1,"%{public}s",password);',
            'empty_value': 'password=""; HILOG_INFO(1,"%{public}s",password);',
        }
        for name, source in cases.items():
            with self.subTest(case=name):
                run = analyze(source)
                self.assertEqual(len(run.findings), 1)
                self.assertEqual(run.status, 'blocked')
                self.assertTrue(run.findings[0].evidence_obligations)
                self.assertIn('heuristic', run.findings[0].message)

    def test_only_explicit_type_alignment_is_nonmaterial(self):
        for expression in ('alignof(decltype(password))', 'sizeof(password)'):
            with self.subTest(expression=expression):
                run = analyze('HILOG_INFO(1,"%{public}zu",' + expression + ');')
                self.assertEqual(len(run.findings), 0)
                self.assertEqual(run.status, 'blocked')  # unknown profile remains unknown

    def test_alignof_does_not_execute_calls_inside_decltype(self):
        run = analyze(
            'HILOG_INFO(1,"%{public}zu",alignof(decltype(UsePassword(password))));',
            prefix='const char *UsePassword(const char *);')
        self.assertEqual(len(run.findings), 0)
        self.assertNotIn('unmodeled call may mutate/escape sensitive value: UsePassword',
                         ' '.join(run.limitations))

    def test_runtime_call_next_to_alignment_still_retains_secret_candidate(self):
        run = analyze(
            'HILOG_INFO(1,"%{public}zu",alignof(decltype(password))); '
            'UsePassword(password);', prefix='const char *UsePassword(const char *);')
        self.assertEqual(len(run.findings), 1)
        self.assertEqual(run.findings[0].rule_id, 'data.sensitive.unresolved-escape')
        self.assertIn('UsePassword', run.findings[0].message)

    def test_arithmetic_beside_alignment_does_not_hide_material(self):
        run = analyze('HILOG_INFO(1,"%{public}u",'
                      '(unsigned)*password + alignof(decltype(password)));')
        self.assertEqual(len(run.findings), 1)
        self.assertIn('password', run.findings[0].message)

    def test_private_material_and_partial_profile_remain_unresolved(self):
        run = analyze('password="hardcoded-secret"; '
                      'HILOG_INFO(1,"%{private}s",password);', partial='partial')
        self.assertEqual(len(run.findings), 1)
        self.assertTrue(any(o.kind == 'sink_privacy' for o in run.findings[0].evidence_obligations))
        self.assertNotEqual(dict(run.file_outcomes)['service.cpp'], 'complete')
        alignment = analyze('HILOG_INFO(1,"%{public}zu",alignof(decltype(password)));', partial='partial')
        self.assertEqual(len(alignment.findings), 0)
        self.assertNotEqual(dict(alignment.file_outcomes)['service.cpp'], 'complete')

    def test_reviewed_source_type_alignment_is_not_material_but_actual_value_is(self):
        run = support.SensitiveTests().analyze(
            'void Callback(unsigned key) {\n'
            'HILOG_INFO(1,"%{public}zu",alignof(decltype(key)));\n'
            'HILOG_INFO(1,"%{public}u",key);\n}')
        self.assertEqual(len(run.findings), 1)
        self.assertIn('Callback parameter 0', run.findings[0].message)
        self.assertEqual(run.findings[0].line, 3)


if __name__ == '__main__':
    unittest.main()
