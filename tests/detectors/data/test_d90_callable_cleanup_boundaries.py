"""D90: cleanup spelling is not proof; callable aliases retain material escapes."""
import unittest

from tests.detectors.data import test_sensitive_exposure as support
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage


class D90CallableCleanupBoundaryTests(unittest.TestCase):
    def findings(self, source, runner=False):
        ctx = support.SensitiveTests().context(source)
        detector = SensitiveExposureDetector(support.MODEL)
        if not runner:
            return detector.detect(ctx, ctx.units).findings
        registry = DetectorRegistry()
        registry.register(detector)
        reports, _ = run_all_with_coverage(ctx, registry)
        return reports[0].diagnostics

    def test_callable_parameter_keeps_sensitive_argument_and_binding_obligation(self):
        source = ('void Callback(const char *key,void(*CfFree)(const char*)){\n'
                  'CfFree(key);\n}')
        for runner in (False, True):
            with self.subTest(runner=runner):
                found = self.findings(source, runner)
                self.assertEqual(len(found), 1)
                self.assertEqual(found[0].line, 2)
                self.assertIn('local callable target', found[0].message)
                self.assertIn('unresolved', found[0].message)

    def test_local_callable_alias_cannot_borrow_named_cleanup_identity(self):
        source = ('void Callback(const char *key,void(*handler)(const char*)){\n'
                  'auto CfFree=handler;\nCfFree(key);\n}')
        for runner in (False, True):
            with self.subTest(runner=runner):
                found = self.findings(source, runner)
                self.assertEqual(len(found), 1)
                self.assertIn('CfFree', found[0].message)
                self.assertIn('source Callback parameter 0', found[0].message)

    def test_shadowed_log_spelling_is_unknown_binding_not_a_proven_log(self):
        found = self.findings('void Callback(const char *key,void(*HILOG_INFO)(const char*)){'
                              'HILOG_INFO(key);}')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].rule_id, 'data.sensitive.unresolved-escape')
        self.assertTrue(any(item.kind == 'callee_binding' for item in found[0].evidence_obligations))

    def test_no_material_argument_does_not_invent_a_callable_escape(self):
        for call in ('CfFree("ordinary text")', 'CfFree(nullptr)'):
            with self.subTest(call=call):
                self.assertEqual(len(self.findings(
                    'void Callback(const char *key,void(*CfFree)(const char*)){'+call+';}')), 0)

    def test_cleanup_names_and_visible_wrapper_keep_unproved_allocator_binding(self):
        for call in ('CfFree(key)', 'CF_FREE_PTR(key)', 'CfBlobDataFree(key)',
                     'memset_s(key,32,0,32)'):
            with self.subTest(call=call):
                self.assertTrue(self.findings('void Callback(char *key){'+call+';}'))
        self.assertTrue(self.findings('#include <stdlib.h>\n'
            'void CfFree(void *addr){if(addr!=NULL){free(addr);}}\n'
            'void Callback(char *key){CfFree(key);}'))

    def test_independent_copy_still_reaches_log_after_cleanup(self):
        source = ('void Callback(char *key,void(*CfFree)(char*)){char copy[32]={0};\n'
                  'memcpy_s(copy,sizeof(copy),key,31);\nCfFree(key);\n'
                  'HILOG_INFO(1,"%{public}s",copy);}')
        found = self.findings(source)
        self.assertEqual(len(found), 2)
        self.assertTrue(any('local callable target' in f.message for f in found))
        self.assertTrue(any(f.line == 4 and 'HILOG_INFO' in f.message for f in found))


if __name__ == '__main__':
    unittest.main()
