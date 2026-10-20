"""T89 independent cleanup-name binding and unresolved callback safety tests."""
from dataclasses import replace
import hashlib
import unittest

from src.ohscanner.contracts import ScanContext, ScanRequest
from src.ohscanner.detectors.data.models import SensitiveSourceModel
from src.ohscanner.detectors.data.sensitive_exposure import SensitiveExposureDetector
from src.ohscanner.fixture import snapshot_digest
from src.ohscanner.frontend import index_sources
from src.ohscanner.git_source import GitSource
from src.ohscanner.runner import DetectorRegistry, run_all_with_coverage


MODEL = SensitiveSourceModel('fixture/t89', 'b' * 40, fields=(), non_sensitive_fields=(),
    output_calls=(), parameters=(('service.cpp', 'Callback', 0),),
    provenance='Synthetic explicit Callback argument source for binding regression; no product claim')


class T89CleanupBindingTests(unittest.TestCase):
    def context(self, source, extra=(), partial=()):
        sources = []
        for path, text in [('service.cpp', source), *extra]:
            data = text.encode()
            oid = hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest()
            sources.append(GitSource(path, 'cpp', oid, data))
        units, ast, _ = index_sources(tuple(sources))
        units = tuple(sorted((replace(unit, parse_status='partial') if unit.path in partial
                              else unit for unit in units), key=lambda unit: unit.path))
        for path in partial:
            ast[path]['parse_status'] = 'partial'
        request = ScanRequest('t89-binding', MODEL.repository, MODEL.commit, snapshot_digest(units),
                              'current-component:' + MODEL.repository)
        return ScanContext(request, units, {'ast': ast})

    def scan(self, source, extra=(), partial=(), runner=False):
        ctx = self.context(source, extra, partial)
        detector = SensitiveExposureDetector(MODEL)
        if runner:
            registry = DetectorRegistry()
            registry.register(detector)
            reports, _ = run_all_with_coverage(ctx, registry)
            return reports[0].diagnostics
        return detector.detect(ctx, ctx.units).findings

    def assert_candidate(self, source, *, message=None, extra=(), partial=()):
        for runner in (False, True):
            with self.subTest(runner=runner):
                findings = self.scan(source, extra, partial, runner)
                self.assertTrue(findings, 'unresolved or leaking binding lost its source')
                if message:
                    self.assertTrue(any(message in finding.message for finding in findings))

    def test_cleanup_spelling_without_definition_is_not_a_proof(self):
        for call in ('CfFree(key)', 'CF_FREE_PTR(key)', 'CfBlobDataFree(key)',
                     'memset_s(key,32,0,32)'):
            with self.subTest(call=call):
                self.assert_candidate('void Callback(char *key){' + call + ';}', message='unresolved')

    def test_exact_same_file_wrapper_still_needs_allocator_binding(self):
        source = '#include <stdlib.h>\nvoid CfFree(void *addr){\n'
        source += 'if(addr!=NULL){free(addr);}\n}\nvoid Callback(char *key){CfFree(key);}'
        self.assert_candidate(source, message='free')

    def test_same_name_local_definition_that_logs_is_analyzed(self):
        self.assert_candidate('void CfFree(const char *addr){\n'
            'HILOG_INFO(1,"%{public}s",addr);\n}\n'
            'void Callback(const char *key){CfFree(key);}', message='HILOG_INFO')

    def test_cross_file_same_name_leaking_definition_is_not_cleanup(self):
        self.assert_candidate('#include "custom.h"\nvoid Callback(char *key){CfFree(key);}',
            extra=(('custom.h', 'void CfFree(char *addr);'),
                   ('custom.cpp', '#include "custom.h"\nvoid CfFree(char *addr){'
                    'HILOG_INFO(1,"%{public}s",addr);}')))

    def test_changed_free_macro_cannot_gain_cleanup_proof(self):
        self.assert_candidate('#include <stdlib.h>\n#undef free\n'
            '#define free(addr) HILOG_INFO(1,"%{public}s",addr)\n'
            'void CfFree(char *addr){if(addr!=NULL){free(addr);}}\n'
            'void Callback(char *key){CfFree(key);}')

    def test_changed_null_macro_cannot_gain_cleanup_proof(self):
        self.assert_candidate('#include <stdlib.h>\nvoid LeakPassword(void *);\n'
            '#undef NULL\n#define NULL (LeakPassword(addr),0)\n'
            'void CfFree(void *addr){if(addr!=NULL){free(addr);}}\n'
            'void Callback(char *key){CfFree(key);}')

    def test_allocator_import_from_custom_namespace_cannot_gain_proof(self):
        self.assert_candidate('namespace N {void free(void *addr){LeakPassword(addr);}}\n'
            'using N::free;\nvoid CfFree(void *addr){if(addr!=NULL){free(addr);}}\n'
            'void Callback(char *key){CfFree(key);}')

    def test_changed_cffree_macro_cannot_gain_cleanup_proof(self):
        self.assert_candidate('#define CfFree(addr) LeakPassword(addr)\n'
            'void Callback(char *key){CfFree(key);}')

    def test_same_name_unknown_namespace_remains_unresolved(self):
        self.assert_candidate('namespace N {void CfFree(char *addr);}\n'
            'void Callback(char *key){N::CfFree(key);}', message='N::CfFree')

    def test_missing_or_partial_header_does_not_prove_cleanup(self):
        source = '#include "custom.h"\nvoid Callback(char *key){CfFree(key);}'
        self.assert_candidate(source)
        self.assert_candidate(source, extra=(('custom.h', 'void CfFree(char *addr);'),),
                              partial=('custom.h',))

    def test_cleanup_and_wipe_do_not_remove_later_material_flow(self):
        for statement in ('CfFree(key);', 'memset_s(key,32,0,32);', 'CF_FREE_PTR(key);'):
            with self.subTest(statement=statement):
                self.assert_candidate('void Callback(char *key){' + statement + '\n'
                    'HILOG_INFO(1,"%{public}s",key);}', message='HILOG_INFO')

    def test_exact_wrapper_does_not_erase_later_actual_log(self):
        self.assert_candidate('#include <stdlib.h>\n#include <securec.h>\n'
            'void CfFree(void *addr){if(addr!=NULL){free(addr);}}\n'
            'void Callback(char *key){char copy[32]={0};\n'
            'memcpy_s(copy,sizeof(copy),key,31); CfFree(key);\n'
            'HILOG_INFO(1,"%{public}s",copy);}', message='HILOG_INFO')

    def test_function_pointer_parameter_named_cffree_remains_unresolved(self):
        self.assert_candidate('void Callback(const char *key,void(*CfFree)(const char*)){\n'
            'CfFree(key);\n}', message='CfFree')

    def test_function_pointer_local_alias_remains_unresolved(self):
        self.assert_candidate('void Callback(const char *key,void(*handler)(const char*)){\n'
            'auto CfFree=handler;\nCfFree(key);\n}', message='CfFree')


if __name__ == '__main__':
    unittest.main()
